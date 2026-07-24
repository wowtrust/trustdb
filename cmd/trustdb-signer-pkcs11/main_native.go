//go:build pkcs11 && cgo

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/wowtrust/trustdb/internal/pkcs11signer"
	"github.com/wowtrust/trustdb/sdk/signerplugin"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), terminationSignals()...)
	defer stop()
	if err := run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "trustdb PKCS#11 signer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	environment, err := pkcs11signer.LoadEnvironment()
	if err != nil {
		return err
	}
	backend, err := pkcs11signer.OpenNativeBackend(environment.ModulePath)
	if err != nil {
		return pkcs11signerSafeError(err)
	}
	plugin, err := pkcs11signer.New(ctx, environment.Config, backend)
	if err != nil {
		_ = backend.Close()
		return err
	}
	defer plugin.Close()
	return signerplugin.Serve(ctx, plugin)
}

func pkcs11signerSafeError(error) error {
	return fmt.Errorf("PKCS#11 module is unavailable")
}
