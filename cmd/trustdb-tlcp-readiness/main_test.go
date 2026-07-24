package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/internal/tlcpprofile"
	"github.com/wowtrust/trustdb/internal/tlcpready"
)

func TestCanaryDeadlineIncludesInitialRuntimeValidation(t *testing.T) {
	t.Setenv("TLCP_PROFILE_FILE", "/strict/profile.json")
	t.Setenv(
		"TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST",
		"sha256:"+strings.Repeat("1", 64),
	)
	started := time.Now()
	current := started
	checkCalled := false
	profile := tlcpprofile.Profile{
		ServerName: "trustdb.test",
		Network: tlcpprofile.Network{
			GatewayHTTPBind: "0.0.0.0:8443",
			GatewayGRPCBind: "0.0.0.0:9443",
		},
		Timeouts: tlcpprofile.Timeouts{Canary: "30s"},
	}
	dependencies := readinessDependencies{
		now: func() time.Time { return current },
		loadProfile: func(string) (tlcpprofile.Profile, error) {
			return profile, nil
		},
		verifyRuntime: func(
			context.Context,
			string,
			tlcpprofile.RuntimeOptions,
		) error {
			current = started.Add(31 * time.Second)
			return nil
		},
		verifyIdentity: func(
			context.Context,
			string,
			tlcpprofile.Profile,
		) error {
			t.Fatal("identity challenge ran after validation exhausted the deadline")
			return nil
		},
		check: func(context.Context, tlcpready.Config) error {
			checkCalled = true
			return nil
		},
	}
	err := runReadiness(dependencies)
	if err == nil || !strings.Contains(err.Error(), "deadline expired") {
		t.Fatalf("runReadiness() error = %v", err)
	}
	if checkCalled {
		t.Fatal("network readiness ran after initial validation exhausted the canary deadline")
	}
}

func TestCanaryDeadlineTerminatesBlockedRuntimeVerifier(t *testing.T) {
	t.Setenv("TLCP_PROFILE_FILE", "/strict/profile.json")
	t.Setenv(
		"TLCP_EXPECTED_GATEWAY_IMAGE_DIGEST",
		"sha256:"+strings.Repeat("1", 64),
	)
	checkCalled := false
	started := time.Now()
	err := runReadiness(readinessDependencies{
		now: time.Now,
		loadProfile: func(string) (tlcpprofile.Profile, error) {
			return tlcpprofile.Profile{
				Timeouts: tlcpprofile.Timeouts{Canary: "1s"},
			}, nil
		},
		verifyRuntime: func(
			ctx context.Context,
			_ string,
			_ tlcpprofile.RuntimeOptions,
		) error {
			<-ctx.Done()
			return ctx.Err()
		},
		verifyIdentity: func(
			context.Context,
			string,
			tlcpprofile.Profile,
		) error {
			t.Fatal("identity challenge ran after a blocked runtime verifier")
			return nil
		},
		check: func(context.Context, tlcpready.Config) error {
			checkCalled = true
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("runReadiness() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("blocked verifier was not terminated by deadline: %s", elapsed)
	}
	if checkCalled {
		t.Fatal("network readiness ran after blocked runtime verification")
	}
}

func TestBoundedVerifierKillsBlockedChildProcess(t *testing.T) {
	if os.Getenv("TRUSTDB_TEST_BLOCKED_TLCP_VERIFIER") == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	t.Setenv("TRUSTDB_TEST_BLOCKED_TLCP_VERIFIER", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := runBoundedVerifier(
		ctx,
		os.Args[0],
		"-test.run=^TestBoundedVerifierKillsBlockedChildProcess$",
	)
	if err == nil || !errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("runBoundedVerifier() error = %v, context = %v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("blocked verifier child was not killed promptly: %s", elapsed)
	}
}
