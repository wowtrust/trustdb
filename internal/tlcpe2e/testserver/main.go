//go:build integration

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	httpListener, err := net.Listen("tcp", "127.0.0.1:18080")
	if err != nil {
		return fmt.Errorf("listen HTTP: %w", err)
	}
	defer httpListener.Close()
	grpcListener, err := net.Listen("tcp", "127.0.0.1:19090")
	if err != nil {
		return fmt.Errorf("listen gRPC: %w", err)
	}
	defer grpcListener.Close()

	mux := http.NewServeMux()
	healthHandler := func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"status":"ok","transport":"loopback"}`))
	}
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/echo-size", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		size, err := io.Copy(io.Discard, request.Body)
		if err != nil {
			http.Error(writer, "read body", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprintf(writer, "%d", size)
	})
	httpServer := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	grpcServer := grpc.NewServer()
	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	errs := make(chan error, 2)
	go func() {
		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("serve HTTP: %w", err)
		}
	}()
	go func() {
		if err := grpcServer.Serve(grpcListener); err != nil {
			errs <- fmt.Errorf("serve gRPC: %w", err)
		}
	}()
	log.Print("TrustDB TLCP E2E upstream ready")

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-errs:
		return err
	case <-signals:
	}
	grpcServer.GracefulStop()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return httpServer.Shutdown(ctx)
}
