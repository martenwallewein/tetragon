// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package netflow

// Map names must match the SEC(".maps") names in bpf_netflow.c
const (
	StateMapName = "state_map"
	RingBufName  = "rb"
)

// EventType corresponds to the enum event_type in C
const (
	EventNormalConnect uint8 = 0
	EventNormalClose   uint8 = 1
	EventAttackStart   uint8 = 2
	EventSummary       uint8 = 3
	EventExfiltration  uint8 = 4
)

// NetflowEvent must be byte-for-byte identical to struct netflow_event in C.
// Ordered largest-to-smallest to prevent implicit padding, totaling exactly 24 bytes.
// Verify with: go test ./pkg/alignchecker/...
type NetflowEvent struct {
	CgroupID        uint64
	DAddr           uint32
	SuppressedCount uint32
	DPort           uint16
	Type            uint8
	Pad             [5]uint8 // Explicit padding to reach 8-byte alignment
}

// RateState mirrors struct rate_state in C (stored in the LRU_PERCPU_HASH map)
type RateState struct {
	WindowStartNS uint64
	Count         uint32
	Suppressed    uint32
}
