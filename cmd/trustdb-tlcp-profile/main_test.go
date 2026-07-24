package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
