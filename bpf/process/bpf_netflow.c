// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_helpers.h"
#include "bpf_tracing.h"

#define WINDOW_SIZE_NS		     1000000000ULL // 1 Second
#define RATE_LIMIT_MAX		     50 // 50 connections per second, per CPU
#define EXFILTRATION_THRESHOLD_BYTES (1024 * 1024 * 100) // 100 MB

// Event Types for the Go Agent to decode
enum event_type {
	EVENT_NORMAL = 0,
	EVENT_ATTACK_START = 1,
	EVENT_SUMMARY = 2,
	EVENT_SUMMARY = 3,
	EVENT_EXFILTRATION = 4,
};

struct netflow_event {
	__u64 cgroup_id; // 8 bytes
	__u32 daddr; // 4 bytes
	__u32 suppressed_count; // 4 bytes
	__u16 dport; // 2 bytes
	__u8 type; // 1 byte
	__u8 pad[5]; // 5 bytes (Pads total to exactly 24 bytes)
};

// The State Tracking Struct stored in the LRU Map
struct rate_state {
	__u64 window_start_ns;
	__u32 count;
	__u32 suppressed;
};

// Map 1: The Ring Buffer (To stream to Go)
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1024 * 1024); // 1 MB buffer
} rb SEC(".maps");

// Map 2: The Rate Limiter State (To track state in-kernel)
struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u64); // Key is cgroup_id (The Pod)
	__type(value, struct rate_state);
} state_map SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_PROG(tg_kp_tcp_connect, struct sock *sk)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u64 now = bpf_ktime_get_ns();

	// 1. Fetch current state for this pod
	struct rate_state *state = bpf_map_lookup_elem(&state_map, &cgroup_id);

	if (!state) {
		// First connection ever. Initialize state and allow.
		struct rate_state new_state = { now, 1, 0 };
		bpf_map_update_elem(&state_map, &cgroup_id, &new_state, BPF_ANY);
		goto emit_normal;
	}

	// 2. Lazy Window Reset Check
	if (now - state->window_start_ns > WINDOW_SIZE_NS) {
		// Did we suppress events in the previous window?
		if (state->suppressed > 0) {
			struct netflow_event *summary = bpf_ringbuf_reserve(&rb, sizeof(*summary), 0);
			if (summary) {
				summary->type = EVENT_SUMMARY;
				summary->cgroup_id = cgroup_id;
				summary->suppressed_count = state->suppressed;
				bpf_ringbuf_submit(summary, 0);
			}
		}

		// Reset the window
		state->window_start_ns = now;
		state->count = 1;
		state->suppressed = 0;
		goto emit_normal;
	}

	// 3. Rate Limit Enforcement
	if (state->count < RATE_LIMIT_MAX) {
		state->count++;
		goto emit_normal;
	} else if (state->count == RATE_LIMIT_MAX) {
		// TRIPWIRE CROSSED! Emit the one-time attack alert.
		state->count++;
		struct netflow_event *attack = bpf_ringbuf_reserve(&rb, sizeof(*attack), 0);
		if (attack) {
			attack->type = EVENT_ATTACK_START;
			attack->cgroup_id = cgroup_id;
			// Capture the IP/Port they are scanning right now
			BPF_CORE_READ_INTO(&attack->daddr, sk, __sk_common.skc_daddr);
			BPF_CORE_READ_INTO(&attack->dport, sk, __sk_common.skc_dport);
			bpf_ringbuf_submit(attack, 0);
		}
		return 0; // Skip normal event
	} else {
		// We are under attack. SILENTLY aggregate. Do NOT touch the Ring Buffer.
		state->suppressed++;
		return 0;
	}

emit_normal: {
	struct netflow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->type = EVENT_NORMAL;
	e->cgroup_id = cgroup_id;
	BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);

	bpf_ringbuf_submit(e, 0);
}
	return 0;
}

SEC("kprobe/tcp_close")
int BPF_PROG(tg_kp_tcp_close, struct sock *sk)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();

	// 1. Check Rate Limit State (Synchronized with tcp_connect)
	struct rate_state *state = bpf_map_lookup_elem(&state_map, &cgroup_id);

	// If the cgroup is actively in an attack state, DO NOT send normal close events.
	// This prevents Ring Buffer flooding when the attacker's sockets are torn down.
	if (state && state->count >= RATE_LIMIT_MAX) {
		// Optional: you could increment a `close_suppressed` counter here if desired.
		return 0;
	}

	// 2. Read TCP Socket Metrics via BTF/CO-RE
	struct tcp_sock *tp = (struct tcp_sock *)sk;
	__u64 rx_bytes = 0;
	__u64 tx_bytes = 0;

	BPF_CORE_READ_INTO(&rx_bytes, tp, bytes_received);
	BPF_CORE_READ_INTO(&tx_bytes, tp, bytes_acked);

	// 3. EXFILTRATION TRIPWIRE
	// Did they send a massive amount of data?
	if (tx_bytes > EXFILTRATION_THRESHOLD_BYTES) {
		struct netflow_event *exfil = bpf_ringbuf_reserve(&rb, sizeof(*exfil), 0);
		if (exfil) {
			exfil->type = EVENT_EXFILTRATION;
			exfil->cgroup_id = cgroup_id;
			// Overload the suppressed_count field to send the byte size,
			// or better yet, add a `bytes` field to the struct.
			exfil->suppressed_count = (__u32)(tx_bytes / 1024 / 1024); // Size in MB

			BPF_CORE_READ_INTO(&exfil->daddr, sk, __sk_common.skc_daddr);
			BPF_CORE_READ_INTO(&exfil->dport, sk, __sk_common.skc_dport);
			bpf_ringbuf_submit(exfil, 0);
		}
		return 0; // We alerted, no need to send the normal close.
	}

	// 4. Normal Path: Emit the close event for SIEM/Splunk
	struct netflow_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e) {
		e->type = EVENT_NORMAL_CLOSE;
		e->cgroup_id = cgroup_id;
		BPF_CORE_READ_INTO(&e->daddr, sk, __sk_common.skc_daddr);
		BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
		// Add rx_bytes and tx_bytes to your netflow_event struct and populate them here
		bpf_ringbuf_submit(e, 0);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";