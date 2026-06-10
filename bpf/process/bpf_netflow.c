// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Tetragon */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "bpf_helpers.h"
#include "bpf_tracing.h"

// Key: identifies a flow. cgroup_id scopes it to a workload.
struct netflow_key {
	__u64 cgroup_id;
	__u32 daddr; // destination IPv4, network byte order
	__u16 dport; // destination port, network byte order
	__u16 pad;
} __attribute__((packed));

// Value: accumulated stats for the flow.
struct netflow_val {
	__u64 conn_count;
	__u64 tx_bytes;
	__u64 rx_bytes;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
	__uint(max_entries, 65536);
	__type(key, struct netflow_key);
	__type(value, struct netflow_val);
} netflow_map SEC(".maps");

SEC("kprobe/tcp_connect")
int tg_kp_tcp_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct netflow_key key = {};
	struct netflow_val first_entry_val = {};
	struct netflow_val *val;

	key.cgroup_id = bpf_get_current_cgroup_id();

	// Ensure proper field is loaded, and ensure kernel memory accessed correctly
	BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&key.dport, sk, __sk_common.skc_dport);

	val = bpf_map_lookup_elem(&netflow_map, &key);
	if (val) {
		// PERCPU maps don't need atomics
		val->conn_count += 1;
	} else {
		first_entry_val.conn_count = 1;
		bpf_map_update_elem(&netflow_map, &key, &first_entry_val, BPF_ANY);
	}
	return 0;
}

SEC("kprobe/tcp_close")
int tg_kp_tcp_close(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct netflow_key key = {};
	struct netflow_val *val;

	key.cgroup_id = bpf_get_current_cgroup_id();
	BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&key.dport, sk, __sk_common.skc_dport);

	val = bpf_map_lookup_elem(&netflow_map, &key);
	if (!val)
		return 0;

	__u64 rx_bytes = 0;
	__u64 tx_bytes = 0;

	struct tcp_sock *tp = (struct tcp_sock *)sk;

	BPF_CORE_READ_INTO(&rx_bytes, tp, bytes_received);
	BPF_CORE_READ_INTO(&tx_bytes, tp, bytes_acked);

	// PERCPU maps don't need atomics
	val->rx_bytes += rx_bytes;
	val->tx_bytes += tx_bytes;
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";