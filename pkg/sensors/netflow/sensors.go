// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package netflow

import (
	"context"

	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var (
	Connect = program.Builder(
		"bpf_netflow.o",
		"tcp_connect",
		"kprobe/tcp_connect",
		"tg_kp_tcp_connect",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	Close = program.Builder(
		"bpf_netflow.o",
		"tcp_close",
		"kprobe/tcp_close",
		"tg_kp_tcp_close",
		"kprobe",
	).SetPolicy(sensors.BaseSensorName)

	// StateMap pins the rate-limiter state at /sys/fs/bpf/tetragon/state_map
	StateMap = program.MapBuilder(StateMapName, Connect, Close)

	// RingBuf registers the perf/ring buffer for the hybrid event stream
	RingBuf = program.MapBuilder(RingBufName, Connect, Close)
)

func GetPrograms() []*program.Program {
	return []*program.Program{Connect, Close}
}

func GetMaps() []*program.Map {
	// Both maps must be registered so the loader initializes them
	return []*program.Map{StateMap, RingBuf}
}

// Add a Load function to initialize the Go reader when the BPF maps are mounted.
func Load(ctx context.Context) error {
	// The Tetragon framework will have already pinned the maps to /sys/fs/bpf/...
	// Now we can safely start our Go reader.
	err := StartNetflowObserver(ctx)
	if err != nil {
		return err
	}
	return nil
}
