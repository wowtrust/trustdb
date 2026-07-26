package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/tlcpprofile"
)

func TestRunRequiresValidateAndProfile(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"other"},
		{"validate"},
		{"validate", "--profile", "relative.json"},
		{"validate", "--profile", "/missing.json", "trailing"},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err == nil {
			t.Fatalf("run(%q) succeeded", args)
		}
		if stdout.Len() != 0 {
			t.Fatalf("run(%q) wrote success output %q", args, stdout.String())
		}
	}
}

func TestStringListRejectsEmptyReferences(t *testing.T) {
	var values stringList
	if err := values.Set("  "); err == nil {
		t.Fatal("empty reference was accepted")
	}
	if err := values.Set("opaque:key"); err != nil {
		t.Fatal(err)
	}
	if got := values.String(); !strings.Contains(got, "opaque:key") {
		t.Fatalf("String() = %q", got)
	}
}

func TestPrepareRuntimeScriptCannotBypassDeadlineThroughEnvironment(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "tlcp-gateway", "prepare-runtime.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	if strings.Contains(script, "TLCP_PREPARE_DEADLINE_ACTIVE") {
		t.Fatal("runtime preparation still trusts an externally forgeable deadline flag")
	}
	if !strings.Contains(
		script,
		"trustdb-tlcp-profile activate-runtime",
	) {
		t.Fatal("runtime preparation does not use the deadline-owning wrapper")
	}
}

func TestInjectedLegacyDeadlineEnvironmentCannotSkipActivationValidation(t *testing.T) {
	t.Setenv("TLCP_PREPARE_DEADLINE_ACTIVE", "1")
	var stdout, stderr bytes.Buffer
	err := run(
		[]string{"activate-runtime", "--lifecycle", "startup"},
		&stdout,
		&stderr,
	)
	if err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("activate-runtime error = %v", err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("activate-runtime wrote success output %q", stdout.String())
	}
}

func TestInitialProfileValidationConsumesTheLifecycleDeadline(t *testing.T) {
	started := time.Unix(100, 0)
	profile := tlcpprofile.Profile{Timeouts: tlcpprofile.Timeouts{
		Startup: "1m30s",
		Reload:  "90s",
		Canary:  "90s",
	}}
	deadline, err := validatedLifecycleDeadline(
		started,
		started.Add(89*time.Second),
		profile,
		tlcpprofile.LifecycleStartup,
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := started.Add(90 * time.Second); !deadline.Equal(want) {
		t.Fatalf("deadline = %s, want %s", deadline, want)
	}
	if _, err := validatedLifecycleDeadline(
		started,
		started.Add(90*time.Second),
		profile,
		tlcpprofile.LifecycleStartup,
	); err == nil {
		t.Fatal("profile validation completing at the deadline was accepted")
	}
}

func TestBoundedActivationOutputRejectsDiagnosticsFlood(t *testing.T) {
	output := &boundedActivationOutput{limit: 4}
	written, err := output.Write([]byte("overflow"))
	if written != 4 || err == nil {
		t.Fatalf("Write() = (%d, %v), want (4, limit error)", written, err)
	}
	if !output.Exceeded() || string(output.Bytes()) != "over" {
		t.Fatalf(
			"bounded activation output = exceeded %v, bytes %q",
			output.Exceeded(),
			output.Bytes(),
		)
	}
}
