//go:build !windows

package main

import (
	"os"
	"syscall"
	"testing"
)

func TestTerminationSignalsIncludeInterruptAndTERM(t *testing.T) {
	t.Parallel()
	signals := terminationSignals()
	if len(signals) != 2 || signals[0] != os.Interrupt || signals[1] != syscall.SIGTERM {
		t.Fatalf("terminationSignals() = %v", signals)
	}
}
