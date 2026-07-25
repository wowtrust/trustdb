package main

import (
	"testing"

	"github.com/wowtrust/trustdb/internal/keyenvelope"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

func TestBackupCommandsDoNotAcceptPassphraseFlags(t *testing.T) {
	cmd := newBackupCommand(&runtimeConfig{})
	for _, name := range []string{"create", "verify", "restore"} {
		subcommand, _, err := cmd.Find([]string{name})
		if err != nil {
			t.Fatalf("find backup %s: %v", name, err)
		}
		if flag := subcommand.Flags().Lookup("passphrase"); flag != nil {
			t.Fatalf("backup %s exposes secret-bearing --passphrase flag", name)
		}
		if flag := subcommand.Flags().Lookup("key-provider"); flag == nil {
			t.Fatalf("backup %s is missing --key-provider", name)
		}
	}
}

func TestBackupKEKProviderFailsClosedForUnknownProvider(t *testing.T) {
	provider, err := backupKEKProvider("external-kek-provider-required")
	if provider != nil || trusterr.CodeOf(err) != trusterr.CodeInvalidArgument {
		t.Fatalf("provider=%v error=%v code=%s", provider, err, trusterr.CodeOf(err))
	}

	provider, err = backupKEKProvider(keyenvelope.PassphraseProvider)
	if err != nil || provider == nil || provider.Name() != keyenvelope.PassphraseProvider {
		t.Fatalf("development provider=%v error=%v", provider, err)
	}
}
