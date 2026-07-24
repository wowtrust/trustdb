package main

import (
	"bytes"
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
