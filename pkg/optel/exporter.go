package optel

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
)

func RunOpenTelemetryExporter() error {
	ctx := context.Background()

	// 1. Configure the gRPC connection to the OTel Collector
	// Replace "localhost" with your 4GB machine's IP if running externally
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint("127.0.0.1:4317"), // Tier 2 Gateway port
		otlpmetricgrpc.WithInsecure(),                 // No TLS for local testing
	)
	if err != nil {
		return fmt.Errorf("Failed to create OTLP exporter: %v", err)
	}

	// 2. Define who is sending the data (Resource metadata)
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceName("metragon-agent"),
		semconv.HostName("node-1"),
	)

	// 3. Set up the Metric Provider
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(5*time.Second))),
		sdkmetric.WithResource(res),
	)
	defer meterProvider.Shutdown(ctx)
	otel.SetMeterProvider(meterProvider)

	// 4. Create an actual Metric (Counter)
	meter := meterProvider.Meter("metragon-ebpf")
	connectionCounter, _ := meter.Int64Counter(
		"network_connections_total",
		metric.WithDescription("Total number of network connections seen by eBPF"),
	)

	// 5. Simulate Tetragon/eBPF reading loop
	log.Println("Metragon Agent Started. Pushing metrics via gRPC...")
	for {
		// In reality, this data comes from reading your eBPF Map
		connectionsObserved := int64(14)

		// Push data to OTel
		connectionCounter.Add(ctx, connectionsObserved)
		log.Printf("Pushed %d connections to OTel Collector\n", connectionsObserved)

		time.Sleep(5 * time.Second)
	}
}
