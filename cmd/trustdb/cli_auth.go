package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
)

const permissionAnnotation = "trustdb.admin.permission"

const (
	adminActorEnv           = "TRUSTDB_ADMIN_ACTOR"
	adminPasswordEnv        = "TRUSTDB_ADMIN_PASSWORD"
	adminPasswordFileEnv    = "TRUSTDB_ADMIN_PASSWORD_FILE"
	adminEmergencyReasonEnv = "TRUSTDB_ADMIN_EMERGENCY_REASON"
)

func requirePermission(command *cobra.Command, permission adminauth.Permission) *cobra.Command {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[permissionAnnotation] = string(permission)
	return command
}

func requiredPermission(command *cobra.Command) adminauth.Permission {
	for current := command; current != nil; current = current.Parent() {
		if value := strings.TrimSpace(current.Annotations[permissionAnnotation]); value != "" {
			return adminauth.Permission(value)
		}
	}
	return ""
}

func (rt *runtimeConfig) authorizeCLI(command *cobra.Command) error {
	permission := requiredPermission(command)
	if permission == "" || !rt.cfg.Admin.CLIEnforce {
		return nil
	}
	store, err := adminauth.NewFileStore(rt.cfg.Admin.PolicyPath)
	if err != nil {
		return err
	}
	now := time.Now()
	policy, _, err := store.Load(now)
	if err != nil {
		return fmt.Errorf("load CLI authorization policy: %w", err)
	}
	manager, err := adminauth.NewManager(policy, now)
	if err != nil {
		return err
	}
	actor := strings.TrimSpace(os.Getenv(adminActorEnv))
	if actor == "" {
		return fmt.Errorf("%s is required for privileged command %q", adminActorEnv, command.CommandPath())
	}
	password, err := adminPassword()
	if err != nil {
		return err
	}
	principal, err := manager.AuthenticateLocal(actor, password, now)
	if err != nil {
		return adminauth.ErrUnauthenticated
	}
	if principal.MFARequired {
		return errors.New("adminauth: MFA-required accounts cannot use the local-password CLI hook")
	}
	if principal.Emergency {
		reason := strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv))
		if len(reason) < 12 || len(reason) > 512 {
			return fmt.Errorf("%s must contain a 12..512 character reason for emergency access", adminEmergencyReasonEnv)
		}
	}
	if _, err := manager.Authorize(principal, permission, now); err != nil {
		return err
	}
	event := rt.logger.Info().Str("actor", principal.AccountID).Str("permission", string(permission)).Str("command", command.CommandPath()).Bool("emergency", principal.Emergency)
	if principal.Emergency {
		event = event.Str("emergency_reason", strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv)))
	}
	event.Msg("privileged CLI command authorized")
	return nil
}

func adminPassword() (string, error) {
	value := os.Getenv(adminPasswordEnv)
	path := strings.TrimSpace(os.Getenv(adminPasswordFileEnv))
	if value != "" && path != "" {
		return "", fmt.Errorf("set only one of %s and %s", adminPasswordEnv, adminPasswordFileEnv)
	}
	if path != "" {
		data, err := adminauth.ReadOwnerOnlyFile(path, 4096)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(string(data))
	}
	if value == "" {
		return "", fmt.Errorf("%s or %s is required", adminPasswordEnv, adminPasswordFileEnv)
	}
	return value, nil
}
