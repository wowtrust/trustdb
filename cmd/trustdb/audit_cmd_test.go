package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
)

func TestCommandAuditActionsCoverSensitiveDomains(t *testing.T) {
	for _, test := range []struct {
		permission adminauth.Permission
		action     string
	}{
		{adminauth.PermissionSystemConfigure, "system.configuration"},
		{adminauth.PermissionSecurityPolicyWrite, "security.policy.update"},
		{adminauth.PermissionKeyManage, "key.lifecycle"},
		{adminauth.PermissionBackupCreate, "backup.create"},
		{adminauth.PermissionBackupRestore, "backup.restore"},
		{adminauth.PermissionAnchorManage, "anchor.configuration"},
		{adminauth.PermissionTrustManage, "trust.configuration"},
	} {
		command := requirePermission(&cobra.Command{Use: "operation"}, test.permission)
		if got := commandAuditAction(command); got != test.action {
			t.Fatalf("permission %s action=%q want=%q", test.permission, got, test.action)
		}
	}
	bootstrap := newAdminPolicyBootstrapCommand(&runtimeConfig{})
	if got := commandAuditAction(bootstrap); got != "security.policy.bootstrap" {
		t.Fatalf("bootstrap action=%q", got)
	}
	recover := newAdminPolicyRecoverCommand(&runtimeConfig{})
	if got := commandAuditAction(recover); got != "security.policy.recover" {
		t.Fatalf("recover action=%q", got)
	}
}

func TestAuditCLIStatusExportAndOfflineVerify(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(dir, "audit.tdkey")
	if err := writeKey(signerPath, privateKey); err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "audit-public.tdkey")
	if err := writeKeyDescriptor(publicPath, testVerifierDescriptor("audit-key", publicKey)); err != nil {
		t.Fatal(err)
	}
	// writeKey derives audit-key from audit.tdkey, matching the public fixture.
	configPath := writeAuditTestConfig(t, dir, signerPath, false, "")

	var statusOut, statusErr bytes.Buffer
	status := newRootCommand(&statusOut, &statusErr)
	status.SetArgs([]string{"--config", configPath, "audit", "status"})
	if err := status.Execute(); err != nil {
		t.Fatalf("status error=%v stderr=%s", err, statusErr.String())
	}
	if !strings.Contains(statusOut.String(), `"ok":true`) {
		t.Fatalf("status output=%s", statusOut.String())
	}

	exportPath := filepath.Join(dir, "security-audit.jsonl")
	var exportOut, exportErr bytes.Buffer
	export := newRootCommand(&exportOut, &exportErr)
	export.SetArgs([]string{"--config", configPath, "audit", "export", "--out", exportPath})
	if err := export.Execute(); err != nil {
		t.Fatalf("export error=%v stderr=%s", err, exportErr.String())
	}
	if info, err := os.Stat(exportPath); err != nil || info.Size() == 0 {
		t.Fatalf("export stat=%v err=%v", info, err)
	}
	checkpointPath := filepath.Join(dir, "security-audit-checkpoint.json")
	checkpoint := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	checkpoint.SetArgs([]string{"--config", configPath, "audit", "checkpoint", "export", "--out", checkpointPath})
	if err := checkpoint.Execute(); err != nil {
		t.Fatal(err)
	}
	checkpointVerifyOut := &bytes.Buffer{}
	checkpointVerify := newRootCommand(checkpointVerifyOut, &bytes.Buffer{})
	checkpointVerify.SetArgs([]string{"--config", configPath, "audit", "checkpoint", "verify", "--file", checkpointPath, "--public-key", publicPath})
	if err := checkpointVerify.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(checkpointVerifyOut.String(), `"network_used":false`) {
		t.Fatalf("checkpoint verify output=%s", checkpointVerifyOut.String())
	}

	var verifyOut, verifyErr bytes.Buffer
	verify := newRootCommand(&verifyOut, &verifyErr)
	verify.SetArgs([]string{"--config", configPath, "audit", "verify", "--file", exportPath, "--public-key", publicPath})
	if err := verify.Execute(); err != nil {
		t.Fatalf("verify error=%v stderr=%s", err, verifyErr.String())
	}
	if !strings.Contains(verifyOut.String(), `"network_used":false`) {
		t.Fatalf("verify output=%s", verifyOut.String())
	}

	data, err := os.ReadFile(exportPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := bytes.Replace(data, []byte(`"result":"authorized"`), []byte(`"result":"authorised"`), 1)
	if bytes.Equal(tampered, data) {
		t.Fatal("test export did not contain authorization event")
	}
	if err := os.WriteFile(exportPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	verify = newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	verify.SetArgs([]string{"--config", configPath, "audit", "verify", "--file", exportPath, "--public-key", publicPath})
	if err := verify.Execute(); err == nil {
		t.Fatal("tampered audit export verified")
	}
}

func TestAuditCLIFailsClosedWhenTrustedTimeIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signerPath := filepath.Join(dir, "audit.tdkey")
	if err := writeKey(signerPath, privateKey); err != nil {
		t.Fatal(err)
	}
	configPath := writeAuditTestConfig(t, dir, signerPath, true, filepath.Join(dir, "missing-time.json"))
	command := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	command.SetArgs([]string{"--config", configPath, "config", "show"})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), "trusted time") {
		t.Fatalf("unsynchronized command error=%v", err)
	}
}

func writeAuditTestConfig(t *testing.T, dir, signerPath string, requireTime bool, referencePath string) string {
	t.Helper()
	configPath := filepath.Join(dir, "trustdb.yaml")
	content := []byte("audit:\n" +
		"  enabled: true\n" +
		"  required: true\n" +
		"  path: " + quoteYAML(filepath.Join(dir, "security.audit")) + "\n" +
		"  checkpoint_path: " + quoteYAML(filepath.Join(dir, "security.checkpoint")) + "\n" +
		"  signing_key: " + quoteYAML(signerPath) + "\n" +
		"  max_bytes: 16777216\n" +
		"  retention: 4380h\n" +
		"  time_reference_path: " + quoteYAML(referencePath) + "\n" +
		"  time_max_sample_age: 2m\n" +
		"  time_max_drift: 5s\n" +
		"  require_synchronized_time: " + fmt.Sprint(requireTime) + "\n")
	if err := os.WriteFile(configPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func quoteYAML(value string) string { return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"` }
