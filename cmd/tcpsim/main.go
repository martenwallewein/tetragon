// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package main

import (
	"fmt"
	"log"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/cilium/tetragon/pkg/metricsconfig"
	"github.com/prometheus/client_golang/prometheus"
)

func main() {

	ListenAddr := "127.0.0.1:8877"

	lAddr, err := net.ResolveTCPAddr("tcp", ListenAddr)
	if err != nil {
		log.Fatal("failed to parse TCP addr ", lAddr, err)
	}

	tcpSocket, err := net.ListenTCP("tcp", lAddr)
	if err != nil {
		log.Fatal("failed to listen on addr ", lAddr, err)
	}

	go func() {
		for {
			conn, err := tcpSocket.Accept()
			if err != nil {
				log.Fatal("failed to accept TCP conn ", err)
			}

			go func() {
				bts := make([]byte, 9000)
				for {
					bts, err := conn.Read(bts)
					if err != nil {
						fmt.Println("failed to read from conn ", err)
						break
					}

					fmt.Println("Read ", bts, " from conn ", conn.RemoteAddr())
				}
			}()
		}
	}()

	var wg sync.WaitGroup

	startPort := 8066
	for i := 0; i < 20; i++ {
		go func(start int) {
			addr := fmt.Sprintf("127.0.0.1:%d", start)
			laddr, err := net.ResolveTCPAddr("tcp", addr)
			if err != nil {
				log.Fatal("failed to parse TCP addr ", addr, err)
			}
			conn, err := net.DialTCP("tcp", laddr, lAddr)
			if err != nil {
				log.Fatal("failed to dial TCP conn ", err)
			}
			fmt.Println("Dialing from ", laddr, " to ", lAddr)

			buf := make([]byte, 9000)
			for j := 0; j < 1000; j++ {
				bts, err := conn.Write(buf)
				if err != nil {
					fmt.Println("failed to write to conn ", err)
					break
				}

				fmt.Println("Write ", bts, " to conn ", conn.LocalAddr())
				time.Sleep(10 * time.Millisecond)
			}

			conn.Close()
		}(startPort)

		startPort++
		wg.Add(1)
	}

	fmt.Println("Tool started")
	wg.Wait()
}

func initMetrics(target string, reg *prometheus.Registry, _ *slog.Logger) error {
	switch target {
	case "health":
		metricsconfig.EnableHealthMetrics(reg).InitForDocs()
	case "resources":
		metricsconfig.InitResourcesMetricsForDocs(reg)
	case "events":
		metricsconfig.InitEventsMetricsForDocs(reg)
	}
	return nil
}
