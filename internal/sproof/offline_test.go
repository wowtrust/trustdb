package sproof

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/verify"
)

func TestVerifyOfflineReportsContainerFailureAndStops(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	proof.FormatVersion = 1
	result, err := VerifyOffline(bytes.NewReader(nil), proof, OfflineTrust{}, OfflineOptions{})
	if err == nil || !strings.Contains(err.Error(), "unsupported format_version") {
		t.Fatalf("VerifyOffline() error = %v", err)
	}
	assertOfflineStage(t, result, OfflineStageContainer, OfflineStageFailed)
	assertOfflineStage(t, result, OfflineStageIdentity, OfflineStageNotRun)
	assertOfflineStage(t, result, string(verify.StageProofBundle), OfflineStageNotRun)
	assertOfflineStage(t, result, string(verify.StageGlobalLog), OfflineStageNotPresent)
	assertOfflineStage(t, result, string(verify.StageAnchor), OfflineStageNotPresent)
	if result.ExternalNetworkAccess || result.ExternalProviderAccess {
		t.Fatalf(
			"VerifyOffline() external access flags = network:%v provider:%v",
			result.ExternalNetworkAccess,
			result.ExternalProviderAccess,
		)
	}
}

func TestVerifyOfflineReportsIdentityFailureBeforeProof(t *testing.T) {
	t.Parallel()

	signingTime := time.Unix(1_700_000_000, 0).UTC()
	descriptor := verifierDescriptor(t, "client-key")
	proof := identityProof(t, cryptosuite.INTLV1, signingTime, descriptor)
	result, err := VerifyOffline(bytes.NewReader(nil), proof, OfflineTrust{
		Identity: IdentityTrust{RequireEvidence: true},
	}, OfflineOptions{})
	if err == nil || !strings.Contains(err.Error(), "verifier-local trust bindings") {
		t.Fatalf("VerifyOffline() error = %v", err)
	}
	assertOfflineStage(t, result, OfflineStageContainer, OfflineStagePassed)
	assertOfflineStage(t, result, OfflineStageIdentity, OfflineStageFailed)
	assertOfflineStage(t, result, string(verify.StageProofBundle), OfflineStageNotRun)
}

func TestVerifyOfflineReportsCryptographicFailureStage(t *testing.T) {
	t.Parallel()

	proof := vectorProof()
	result, err := VerifyOffline(bytes.NewReader(nil), proof, OfflineTrust{}, OfflineOptions{})
	if err == nil {
		t.Fatal("VerifyOffline() error = nil")
	}
	assertOfflineStage(t, result, OfflineStageContainer, OfflineStagePassed)
	assertOfflineStage(t, result, OfflineStageIdentity, OfflineStageNotPresent)
	assertOfflineStage(t, result, string(verify.StageProofBundle), OfflineStagePassed)
	assertOfflineStage(t, result, string(verify.StageContent), OfflineStageFailed)
	assertOfflineStage(t, result, string(verify.StageClientClaim), OfflineStageNotRun)
}

func assertOfflineStage(
	t *testing.T,
	result OfflineResult,
	name string,
	status OfflineStageStatus,
) {
	t.Helper()
	for _, stage := range result.Stages {
		if stage.Name == name {
			if stage.Status != status {
				t.Fatalf("stage %q status = %q, want %q; stages=%+v", name, stage.Status, status, result.Stages)
			}
			return
		}
	}
	t.Fatalf("stage %q is missing; stages=%+v", name, result.Stages)
}
