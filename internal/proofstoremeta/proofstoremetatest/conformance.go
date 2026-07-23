// Package proofstoremetatest provides the shared immutable suite-marker
// contract used by file, Pebble, and TiKV backend tests.
package proofstoremetatest

import (
	"errors"
	"testing"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

// Harness exposes only the storage-engine primitives needed to prove that
// every backend applies the same fail-closed namespace contract. Each
// conformance subtest receives a fresh namespace.
type Harness struct {
	Open           func(cryptosuite.ID) (cryptosuite.ID, error)
	SeedUnbound    func() error
	WriteRawMarker func([]byte) error
}

type HarnessFactory func(*testing.T) Harness

func Run(t *testing.T, newHarness HarnessFactory) {
	t.Helper()
	t.Run("InitializeReopenAndRejectMismatch", func(t *testing.T) {
		h := newHarness(t)
		actual, err := h.Open(cryptosuite.INTLV1)
		if err != nil || actual != cryptosuite.INTLV1 {
			t.Fatalf("initialize suite = %q, err=%v", actual, err)
		}
		actual, err = h.Open(cryptosuite.INTLV1)
		if err != nil || actual != cryptosuite.INTLV1 {
			t.Fatalf("reopen suite = %q, err=%v", actual, err)
		}
		if _, err := h.Open(cryptosuite.CNSMV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("mismatch code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("RejectUnboundNonEmptyNamespace", func(t *testing.T) {
		h := newHarness(t)
		if err := h.SeedUnbound(); err != nil {
			t.Fatalf("SeedUnbound: %v", err)
		}
		if _, err := h.Open(cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("unbound code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("RejectCorruptMarker", func(t *testing.T) {
		h := newHarness(t)
		if err := h.WriteRawMarker([]byte{0xff}); err != nil {
			t.Fatalf("WriteRawMarker: %v", err)
		}
		if _, err := h.Open(cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeDataLoss {
			t.Fatalf("corrupt code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("RejectUnknownMarkerSuite", func(t *testing.T) {
		h := newHarness(t)
		marker, err := proofstoremeta.New(cryptosuite.INTLV1)
		if err != nil {
			t.Fatal(err)
		}
		marker.CryptoSuite = cryptosuite.ID("UNKNOWN")
		data, err := cborx.Marshal(marker)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.WriteRawMarker(data); err != nil {
			t.Fatalf("WriteRawMarker: %v", err)
		}
		if _, err := h.Open(cryptosuite.INTLV1); trusterr.CodeOf(err) != trusterr.CodeFailedPrecondition {
			t.Fatalf("unknown code=%s err=%v", trusterr.CodeOf(err), err)
		}
	})
	t.Run("RejectUnknownConfiguredSuite", func(t *testing.T) {
		h := newHarness(t)
		_, err := h.Open(cryptosuite.ID("unknown"))
		if err == nil || (!errors.Is(err, cryptosuite.ErrUnknownSuite) && trusterr.CodeOf(err) != trusterr.CodeInvalidArgument) {
			t.Fatalf("unknown configured suite err=%v", err)
		}
	})
}
