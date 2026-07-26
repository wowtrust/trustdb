//go:build sdf && cgo && (linux || darwin)

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/wowtrust/trustdb/v2/internal/sdfsigner"
	"github.com/wowtrust/trustdb/v2/sdk/signerplugin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "trustdb SDF signer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	environment, err := sdfsigner.LoadEnvironment()
	if err != nil {
		return err
	}
	backend, err := sdfsigner.OpenNativeBackend(environment.AdapterPath, environment.AdapterConfig)
	clear(environment.AdapterConfig)
	environment.AdapterConfig = nil
	if err != nil {
		return sdfsignerSafeError(err)
	}
	plugin, err := sdfsigner.New(ctx, environment.Config, backend)
	if err != nil {
		_ = backend.Close()
		return err
	}
	defer plugin.Close()
	return signerplugin.Serve(ctx, plugin)
}

func sdfsignerSafeError(error) error {
	return fmt.Errorf("SDF adapter is unavailable")
}
