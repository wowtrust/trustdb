package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	trustconfig "github.com/wowtrust/trustdb/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func TestPrivilegedCommandPermissionAnnotations(t *testing.T) {
	t.Parallel()
	root := newRootCommand(&bytes.Buffer{}, &bytes.Buffer{})
	for _, test := range []struct {
		args []string
		want adminauth.Permission
	}{
		{[]string{"serve"}, adminauth.PermissionSystemOperate},
		{[]string{"config", "init"}, adminauth.PermissionSystemConfigure},
		{[]string{"config", "show"}, adminauth.PermissionSystemRead},
		{[]string{"key", "inspect"}, adminauth.PermissionKeyRead},
		{[]string{"key", "rotate"}, adminauth.PermissionKeyManage},
		{[]string{"backup", "create"}, adminauth.PermissionBackupCreate},
		{[]string{"backup", "restore"}, adminauth.PermissionBackupRestore},
		{[]string{"anchor", "export"}, adminauth.PermissionAnchorRead},
		{[]string{"anchor", "upgrade"}, adminauth.PermissionAnchorManage},
		{[]string{"anchor", "fisco-bcos", "trust-config", "advance"}, adminauth.PermissionTrustManage},
		{[]string{"wal", "dump"}, adminauth.PermissionAuditRead},
		{[]string{"wal", "repair"}, adminauth.PermissionSystemOperate},
		{[]string{"metastore", "migrate"}, adminauth.PermissionSystemOperate},
	} {
		command, _, err := root.Find(test.args)
		if err != nil {
			t.Fatalf("Find(%v): %v", test.args, err)
		}
		if got := requiredPermission(command); got != test.want {
			t.Errorf("requiredPermission(%v)=%q want %q", test.args, got, test.want)
		}
	}
}

func TestCLIAuthorizationAllowsOnlyGrantedRole(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-policy.json")
	hash, err := bcrypt.GenerateFromPassword([]byte("a sufficiently long password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	policy := adminauth.Policy{
		SchemaVersion: adminauth.PolicySchema, Version: 1,
		Accounts: []adminauth.Account{
			{ID: "audit", Username: "audit", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleAuditAdmin}, SessionEpoch: 1},
			{ID: "backup", Username: "backup", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleBackupOperator}, SessionEpoch: 1},
			{ID: "security", Username: "security", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleSecurityAdmin}, SessionEpoch: 1},
			{ID: "system", Username: "system", PasswordHash: string(hash), Roles: []adminauth.Role{adminauth.RoleSystemAdmin}, SessionEpoch: 1},
		},
	}
	store, _ := adminauth.NewFileStore(path)
	if _, err := store.Bootstrap(policy, time.Now()); err != nil {
		t.Fatal(err)
	}
	rt := &runtimeConfig{cfg: trustconfig.Config{Admin: trustconfig.Admin{CLIEnforce: true, PolicyPath: path}}, logger: zerolog.Nop()}
	command := requirePermission(&cobra.Command{Use: "restore"}, adminauth.PermissionBackupRestore)
	t.Setenv(adminActorEnv, "system")
	t.Setenv(adminPasswordEnv, "a sufficiently long password")
	if err := rt.authorizeCLI(command); !errors.Is(err, adminauth.ErrPermissionDenied) {
		t.Fatalf("system authorize backup.restore error=%v", err)
	}
	t.Setenv(adminActorEnv, "backup")
	if err := rt.authorizeCLI(command); err != nil {
		t.Fatalf("backup authorize backup.restore error=%v", err)
	}
}

func TestAdminPolicyBootstrapCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin-policy.json")
	t.Setenv("TRUSTDB_ADMIN_BOOTSTRAP_SYSTEM_PASSWORD", "system bootstrap password")
	t.Setenv("TRUSTDB_ADMIN_BOOTSTRAP_SECURITY_PASSWORD", "security bootstrap password")
	t.Setenv("TRUSTDB_ADMIN_BOOTSTRAP_AUDIT_PASSWORD", "audit bootstrap password")
	var stdout, stderr bytes.Buffer
	command := newRootCommand(&stdout, &stderr)
	command.SetArgs([]string{"admin", "policy", "bootstrap", "--out", path})
	if err := command.Execute(); err != nil {
		t.Fatalf("bootstrap error=%v stderr=%s", err, stderr.String())
	}
	store, err := adminauth.NewFileStore(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, digest, err := store.Load(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version != 1 || len(policy.Accounts) != 3 || !strings.Contains(stdout.String(), digest) {
		t.Fatalf("bootstrap policy=%+v stdout=%s", policy, stdout.String())
	}
}

func TestAdminPolicyOfflineRecoveryRequiresReason(t *testing.T) {
	t.Setenv(adminEmergencyReasonEnv, "")
	rt := &runtimeConfig{cfg: trustconfig.Default(), logger: zerolog.Nop()}
	command := newAdminPolicyRecoverCommand(rt)
	command.SetArgs([]string{
		"--offline-recovery",
		"--file", filepath.Join(t.TempDir(), "admin-policy.json"),
		"--replacement", filepath.Join(t.TempDir(), "replacement.json"),
		"--expect-current-digest", strings.Repeat("0", 64),
	})
	if err := command.Execute(); err == nil || !strings.Contains(err.Error(), adminEmergencyReasonEnv) {
		t.Fatalf("policy recover error = %v, want mandatory recovery reason", err)
	}
}
