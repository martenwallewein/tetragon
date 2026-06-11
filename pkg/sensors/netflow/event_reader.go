// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package netflow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/tetragon/pkg/option"
)

// StartNetflowObserver starts a background goroutine to process hybrid events.
// It should be called during Tetragon's startup sequence.
func StartNetflowObserver(ctx context.Context) error {
	// 1. Locate the pinned ring buffer map
	mapPath := filepath.Join(option.Config.BpfDir, RingBufName)

	// 2. Open the BPF map from the virtual file system
	bpfMap, err := ebpf.LoadPinnedMap(mapPath, nil)
	if err != nil {
		return err
	}

	// 3. Create the Ringbuf Reader
	reader, err := ringbuf.NewReader(bpfMap)
	if err != nil {
		bpfMap.Close()
		return err
	}

	log.Println("Netflow hybrid observer started successfully.")

	// 4. Start the background consumption loop
	go func() {
		// Ensure resources are cleaned up when the context is canceled
		defer bpfMap.Close()
		defer reader.Close()

		for {
			// Check if we are shutting down
			if ctx.Err() != nil {
				return
			}

			// Read blocks until an event is available or the reader is closed
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Netflow ringbuf reader closed")
					return
				}
				log.Printf("Error reading from netflow ringbuf: %v", err)
				continue
			}

			// Pass the raw byte slice to our handler
			handleRingbufRecord(record.RawSample)
		}
	}()

	// 5. Handle graceful shutdown
	go func() {
		<-ctx.Done()
		// Closing the reader forces reader.Read() to unblock and return ErrClosed
		reader.Close()
	}()

	return nil
}

// handleRingbufRecord deserializes the C struct and routes the event
func handleRingbufRecord(rawSample []byte) {
	var event NetflowEvent

	// We use binary.Read because we ensured strict 24-byte alignment in map.go
	err := binary.Read(bytes.NewReader(rawSample), binary.LittleEndian, &event)
	if err != nil {
		log.Printf("Failed to decode netflow event: %v", err)
		return
	}

	// Route based on the Hybrid Threat Detection logic
	switch event.Type {
	case EventNormalConnect:
		// Optional: Log or send to SIEM (can be extremely high volume)
		// log.Printf("CONNECT: cgroup %d -> %s:%d", event.CgroupID, int32ToIP(event.DAddr), event.DPort)

	case EventNormalClose:
		// Optional: Log or send to SIEM

	case EventAttackStart:
		log.Printf("🚨 CRITICAL: Port Scan/Volumetric Attack Detected! Cgroup %d crossed threshold targeting %s:%d",
			event.CgroupID, int2ip(event.DAddr), event.DPort)

	case EventSummary:
		log.Printf("📊 METRIC: Suppressed %d normal events during attack spike for cgroup %d",
			event.SuppressedCount, event.CgroupID)

		// TODO: Push event.SuppressedCount to Prometheus/Splunk

	case EventExfiltration:
		log.Printf("🚨 CRITICAL: Data Exfiltration Detected! %d MB transferred by cgroup %d",
			event.SuppressedCount, event.CgroupID)
	}
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}
