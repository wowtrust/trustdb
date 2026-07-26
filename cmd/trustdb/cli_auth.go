package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/v2/internal/adminauth"
	"github.com/wowtrust/trustdb/v2/internal/securityaudit"
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
	if permission == "" {
		if commandAuditAction(command) == "" {
			return nil
		}
		rt.auditActor = localAuditActor()
		rt.auditRoles = []string{"local-operator"}
		contextValues := map[string]string{"auth_method": "os-local"}
		if commandAuditAction(command) == "security.policy.recover" {
			contextValues["emergency"] = "true"
			contextValues["emergency_reason_digest"] = auditReasonDigest(strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv)))
		}
		if err := rt.auditRecord(command.Context(), securityaudit.Draft{
			Action: "cli.authorization", Object: command.CommandPath(), Result: "authorized", Source: "cli", Context: contextValues,
		}); err != nil {
			return fmt.Errorf("record local CLI authorization: %w", err)
		}
		return nil
	}
	if !rt.cfg.Admin.CLIEnforce {
		rt.auditActor = localAuditActor()
		rt.auditRoles = []string{"local-operator"}
		if err := rt.auditRecord(command.Context(), securityaudit.Draft{
			Action: "cli.authorization", Object: command.CommandPath(), Result: "authorized",
			Source: "cli", Context: map[string]string{"permission": string(permission), "auth_method": "os-local-unenforced"},
		}); err != nil {
			return fmt.Errorf("record unenforced CLI authorization: %w", err)
		}
		return nil
	}
	store, err := adminauth.NewFileStore(rt.cfg.Admin.PolicyPath)
	if err != nil {
		return err
	}
	now := time.Now()
	policy, _, err := store.Load(now)
	if err != nil {
		_ = rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: localAuditActor(), Action: "cli.authentication", Object: command.CommandPath(), Result: "failure",
			Source: "cli", Context: map[string]string{"permission": string(permission), "failure_stage": "policy-load"},
		})
		return fmt.Errorf("load CLI authorization policy: %w", err)
	}
	manager, err := adminauth.NewManager(policy, now)
	if err != nil {
		return err
	}
	actor := strings.TrimSpace(os.Getenv(adminActorEnv))
	if actor == "" {
		if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: localAuditActor(), Action: "cli.authentication", Object: command.CommandPath(), Result: "denied",
			Source: "cli", PolicyVersion: policy.Version, Context: map[string]string{"permission": string(permission), "failure_stage": "actor-missing"},
		}); auditErr != nil {
			return errors.Join(fmt.Errorf("%s is required for privileged command %q", adminActorEnv, command.CommandPath()), auditErr)
		}
		return fmt.Errorf("%s is required for privileged command %q", adminActorEnv, command.CommandPath())
	}
	password, err := adminPassword()
	if err != nil {
		if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: actor, Action: "cli.authentication", Object: command.CommandPath(), Result: "denied",
			Source: "cli", PolicyVersion: policy.Version, Context: map[string]string{"permission": string(permission), "failure_stage": "credential-input"},
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}
	principal, err := manager.AuthenticateLocal(actor, password, now)
	if err != nil {
		if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: actor, Action: "cli.authentication", Object: command.CommandPath(), Result: "denied",
			Source: "cli", PolicyVersion: policy.Version, Context: map[string]string{"permission": string(permission), "auth_method": "local-password"},
		}); auditErr != nil {
			return errors.Join(adminauth.ErrUnauthenticated, auditErr)
		}
		return adminauth.ErrUnauthenticated
	}
	if principal.MFARequired {
		err := errors.New("adminauth: MFA-required accounts cannot use the local-password CLI hook")
		if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: principal.AccountID, Roles: principalAuditRoles(principal), Action: "cli.authentication",
			Object: command.CommandPath(), Result: "denied", Source: "cli", PolicyVersion: principal.PolicyVersion,
			Context: map[string]string{"permission": string(permission), "failure_stage": "mfa-required"},
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}
	if principal.Emergency {
		reason := strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv))
		if len(reason) < 12 || len(reason) > 512 {
			err := fmt.Errorf("%s must contain a 12..512 character reason for emergency access", adminEmergencyReasonEnv)
			if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
				Actor: principal.AccountID, Roles: principalAuditRoles(principal), Action: "cli.authentication",
				Object: command.CommandPath(), Result: "denied", Source: "cli", PolicyVersion: principal.PolicyVersion,
				Context: map[string]string{"permission": string(permission), "failure_stage": "emergency-reason-invalid"},
			}); auditErr != nil {
				return errors.Join(err, auditErr)
			}
			return err
		}
	}
	if _, err := manager.Authorize(principal, permission, now); err != nil {
		if auditErr := rt.auditRecord(command.Context(), securityaudit.Draft{
			Actor: principal.AccountID, Roles: principalAuditRoles(principal), Action: "cli.authorization",
			Object: command.CommandPath(), Result: "denied", Source: "cli", PolicyVersion: principal.PolicyVersion,
			Context: map[string]string{"permission": string(permission), "auth_method": string(principal.AuthMethod)},
		}); auditErr != nil {
			return errors.Join(err, auditErr)
		}
		return err
	}
	rt.auditActor = principal.AccountID
	rt.auditRoles = principalAuditRoles(principal)
	rt.auditPolicy = principal.PolicyVersion
	contextValues := map[string]string{"permission": string(permission), "auth_method": string(principal.AuthMethod)}
	if principal.Emergency {
		contextValues["emergency"] = "true"
		contextValues["emergency_reason_digest"] = auditReasonDigest(strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv)))
	}
	if err := rt.auditRecord(command.Context(), securityaudit.Draft{
		Actor: principal.AccountID, Roles: principalAuditRoles(principal), Action: "cli.authorization",
		Object: command.CommandPath(), Result: "authorized", Source: "cli", PolicyVersion: principal.PolicyVersion,
		Context: contextValues,
	}); err != nil {
		return fmt.Errorf("record CLI authorization: %w", err)
	}
	event := rt.logger.Info().Str("actor", principal.AccountID).Str("permission", string(permission)).Str("command", command.CommandPath()).Bool("emergency", principal.Emergency)
	if principal.Emergency {
		event = event.Str("emergency_reason_digest", auditReasonDigest(strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv))))
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
