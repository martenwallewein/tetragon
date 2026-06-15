package netflow

import (
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/option"
)

func GetMetrics() error {
	// 1. Open the pinned State Map
	mapPath := filepath.Join(option.Config.BpfDir, StateMapName)
	stateMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return fmt.Errorf("failed to load state_map: %w", err)
	}
	defer stateMap.Close()

	var key uint64             // cgroup_id
	var perCPUVals []RateState // Because it's a PERCPU map, we get a slice of states!

	// Iterate over the entire BPF map
	iter := stateMap.Iterate()
	for iter.Next(&key, &perCPUVals) {

		var totalCount uint32 = 0
		// Sum the values across all CPU cores
		for _, cpuVal := range perCPUVals {
			totalCount += cpuVal.Count
		}

		podID := fmt.Sprintf("%d", key)

		// Add metrics here
		fmt.Println("Collect metrics for Pod ", podID)
	}

	err = iter.Err()
	if err != nil {
		return err
	}

	return nil

}
