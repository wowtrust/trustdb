package main

import (
	"context"
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
	dependencies := readinessDependencies{
		now: func() time.Time { return current },
		verifyRuntime: func(
			string,
			tlcpprofile.RuntimeOptions,
		) (tlcpprofile.RuntimeManifest, error) {
			current = started.Add(31 * time.Second)
			return tlcpprofile.RuntimeManifest{}, nil
		},
		loadAndValidate: func(
			string,
			tlcpprofile.Options,
		) (tlcpprofile.Profile, tlcpprofile.Report, error) {
			return tlcpprofile.Profile{
				ServerName: "trustdb.test",
				Network: tlcpprofile.Network{
					GatewayHTTPBind: "0.0.0.0:8443",
					GatewayGRPCBind: "0.0.0.0:9443",
				},
				Timeouts: tlcpprofile.Timeouts{Canary: "30s"},
			}, tlcpprofile.Report{}, nil
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
