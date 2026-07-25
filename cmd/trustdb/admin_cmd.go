package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	"golang.org/x/crypto/bcrypt"
)

func newAdminCommand(rt *runtimeConfig) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "admin",
		Short: "Operator utilities for TrustDB admin web",
	}
	cmd.AddCommand(newAdminHashPasswordCommand())
	cmd.AddCommand(newAdminPolicyCommand(rt))
	return cmd
}

func newAdminPolicyCommand(rt *runtimeConfig) *cobra.Command {
	command := &cobra.Command{Use: "policy", Short: "Bootstrap, inspect, validate, and recover the administrative RBAC policy"}
	command.AddCommand(newAdminPolicyBootstrapCommand(rt))
	command.AddCommand(newAdminPolicyInspectCommand(rt))
	command.AddCommand(newAdminPolicyValidateCommand(rt))
	command.AddCommand(newAdminPolicyRecoverCommand(rt))
	return command
}

func newAdminPolicyBootstrapCommand(rt *runtimeConfig) *cobra.Command {
	var output, systemUsername, securityUsername, auditUsername string
	command := &cobra.Command{
		Use:   "bootstrap",
		Short: "Create the first separated system/security/audit administrator policy",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			actor, err := localOSActor()
			if err != nil {
				return err
			}
			if strings.TrimSpace(output) == "" {
				output = rt.cfg.Admin.PolicyPath
			}
			passwords := make(map[string]string, 3)
			for _, role := range []string{"SYSTEM", "SECURITY", "AUDIT"} {
				value, err := bootstrapPassword(role)
				if err != nil {
					return err
				}
				passwords[role] = value
			}
			hashes := make(map[string]string, 3)
			for role, password := range passwords {
				hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				hashes[role] = string(hash)
			}
			policy := adminauth.Policy{
				SchemaVersion: adminauth.PolicySchema, Version: 1,
				Accounts: []adminauth.Account{
					{ID: "audit-admin", Username: auditUsername, PasswordHash: hashes["AUDIT"], Roles: []adminauth.Role{adminauth.RoleAuditAdmin}, SessionEpoch: 1, Description: "Separated audit administrator"},
					{ID: "security-admin", Username: securityUsername, PasswordHash: hashes["SECURITY"], Roles: []adminauth.Role{adminauth.RoleSecurityAdmin}, SessionEpoch: 1, Description: "Separated security administrator"},
					{ID: "system-admin", Username: systemUsername, PasswordHash: hashes["SYSTEM"], Roles: []adminauth.Role{adminauth.RoleSystemAdmin}, SessionEpoch: 1, Description: "Separated system administrator"},
				},
			}
			store, err := adminauth.NewFileStore(output)
			if err != nil {
				return err
			}
			digest, err := store.Bootstrap(policy, time.Now())
			if err != nil {
				return err
			}
			rt.logger.Info().Str("actor", actor).Str("policy_path", store.Path()).Str("policy_digest", digest).Msg("administrative policy bootstrapped")
			return rt.writeJSON(map[string]any{"actor": actor, "policy_path": store.Path(), "schema_version": adminauth.PolicySchema, "version": 1, "digest": digest})
		},
	}
	command.Flags().StringVar(&output, "out", "", "policy output path (defaults to admin.policy_path)")
	command.Flags().StringVar(&systemUsername, "system-username", "system-admin", "system administrator login name")
	command.Flags().StringVar(&securityUsername, "security-username", "security-admin", "security administrator login name")
	command.Flags().StringVar(&auditUsername, "audit-username", "audit-admin", "audit administrator login name")
	return command
}

func bootstrapPassword(role string) (string, error) {
	valueName := "TRUSTDB_ADMIN_BOOTSTRAP_" + role + "_PASSWORD"
	fileName := valueName + "_FILE"
	value := os.Getenv(valueName)
	filePath := strings.TrimSpace(os.Getenv(fileName))
	if value != "" && filePath != "" {
		return "", fmt.Errorf("set only one of %s and %s", valueName, fileName)
	}
	if filePath != "" {
		data, err := adminauth.ReadOwnerOnlyFile(filePath, 4096)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(data))
	}
	if len(value) < 12 {
		return "", fmt.Errorf("%s or %s must provide at least 12 characters", valueName, fileName)
	}
	return value, nil
}

func newAdminPolicyInspectCommand(rt *runtimeConfig) *cobra.Command {
	var file string
	command := &cobra.Command{
		Use: "inspect", Short: "Print a redacted policy summary and digest", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, digest, path, err := loadAdminPolicyForCommand(rt, file)
			if err != nil {
				return err
			}
			for index := range policy.Accounts {
				if policy.Accounts[index].PasswordHash != "" {
					policy.Accounts[index].PasswordHash = "<configured>"
				}
			}
			return rt.writeJSON(map[string]any{"policy_path": path, "digest": digest, "policy": policy})
		},
	}
	command.Flags().StringVar(&file, "file", "", "policy path (defaults to admin.policy_path)")
	return requirePermission(command, adminauth.PermissionSecurityPolicyRead)
}

func newAdminPolicyValidateCommand(rt *runtimeConfig) *cobra.Command {
	var file string
	command := &cobra.Command{
		Use: "validate", Short: "Strictly validate an administrative policy", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			policy, digest, path, err := loadAdminPolicyForCommand(rt, file)
			if err != nil {
				return err
			}
			return rt.writeJSON(map[string]any{"valid": true, "policy_path": path, "schema_version": policy.SchemaVersion, "version": policy.Version, "digest": digest})
		},
	}
	command.Flags().StringVar(&file, "file", "", "policy path (defaults to admin.policy_path)")
	return command
}

func newAdminPolicyRecoverCommand(rt *runtimeConfig) *cobra.Command {
	var file, replacement, expectedDigest string
	var confirmed bool
	command := &cobra.Command{
		Use: "recover", Short: "Offline recovery: atomically install a validated next policy revision", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !confirmed {
				return usageError("--offline-recovery is required")
			}
			actor, err := localOSActor()
			if err != nil {
				return err
			}
			reason := strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv))
			if len(reason) < 12 || len(reason) > 512 {
				return fmt.Errorf("%s must contain a 12..512 character reason for offline recovery", adminEmergencyReasonEnv)
			}
			if strings.TrimSpace(file) == "" {
				file = rt.cfg.Admin.PolicyPath
			}
			if strings.TrimSpace(replacement) == "" || strings.TrimSpace(expectedDigest) == "" {
				return usageError("--replacement and --expect-current-digest are required")
			}
			data, err := adminauth.ReadOwnerOnlyFile(replacement, adminauth.MaxPolicyBytes)
			if err != nil {
				return err
			}
			next, err := adminauth.ParsePolicy(data, time.Now())
			if err != nil {
				return err
			}
			store, err := adminauth.NewFileStore(file)
			if err != nil {
				return err
			}
			digest, err := store.ReplaceOffline(strings.TrimSpace(expectedDigest), next, time.Now())
			if err != nil {
				return err
			}
			rt.logger.Warn().Str("actor", actor).Str("emergency_reason", reason).Str("policy_path", store.Path()).Uint64("policy_version", next.Version).Str("policy_digest", digest).Msg("administrative policy recovered offline")
			return rt.writeJSON(map[string]any{"recovered": true, "actor": actor, "policy_path": store.Path(), "version": next.Version, "digest": digest})
		},
	}
	command.Flags().StringVar(&file, "file", "", "current policy path (defaults to admin.policy_path)")
	command.Flags().StringVar(&replacement, "replacement", "", "validated replacement policy JSON")
	command.Flags().StringVar(&expectedDigest, "expect-current-digest", "", "required current policy digest")
	command.Flags().BoolVar(&confirmed, "offline-recovery", false, "confirm use of the break-glass offline recovery path")
	return command
}

func localOSActor() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("resolve operating-system actor: %w", err)
	}
	username := strings.TrimSpace(current.Username)
	if username == "" {
		return "", errors.New("resolve operating-system actor: username is empty")
	}
	return "os:" + username, nil
}

func loadAdminPolicyForCommand(rt *runtimeConfig, path string) (adminauth.Policy, string, string, error) {
	if strings.TrimSpace(path) == "" {
		path = rt.cfg.Admin.PolicyPath
	}
	store, err := adminauth.NewFileStore(path)
	if err != nil {
		return adminauth.Policy{}, "", "", err
	}
	policy, digest, err := store.Load(time.Now())
	return policy, digest, store.Path(), err
}

func newAdminHashPasswordCommand() *cobra.Command {
	var passwordFile string
	cmd := &cobra.Command{
		Use:   "hash-password",
		Short: "Print a bcrypt verifier for a manually authored policy account",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(passwordFile) == "" {
				return usageError("--password-file is required")
			}
			data, err := adminauth.ReadOwnerOnlyFile(passwordFile, 4096)
			if err != nil {
				return err
			}
			secret := strings.TrimSpace(string(data))
			if secret == "" {
				return usageError("password is required")
			}
			out, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
	cmd.Flags().StringVar(&passwordFile, "password-file", "", "owner-only password file")
	return cmd
}
