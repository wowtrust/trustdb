package main

import "testing"

func TestVersionUsesInjectedReleaseVersion(t *testing.T) {
	previous := desktopVersion
	desktopVersion = "1.0.0-beta"
	t.Cleanup(func() {
		desktopVersion = previous
	})

	if got := NewApp().Version(); got != "1.0.0-beta" {
		t.Fatalf("Version() = %q, want %q", got, "1.0.0-beta")
	}
}
