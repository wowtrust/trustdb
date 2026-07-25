package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wowtrust/trustdb/internal/adminauth"
	"github.com/wowtrust/trustdb/internal/securityaudit"
	"github.com/wowtrust/trustdb/internal/trusterr"
)

const auditActionAnnotation = "trustdb.security-audit.action"

func (rt *runtimeConfig) initAudit(command *cobra.Command) error {
	if rt.auditor != nil || !rt.cfg.Audit.Enabled || commandAuditAction(command) == "" {
		return nil
	}
	retention, err := time.ParseDuration(rt.cfg.Audit.Retention)
	if err != nil {
		return err
	}
	maxSampleAge, err := time.ParseDuration(rt.cfg.Audit.TimeMaxSampleAge)
	if err != nil {
		return err
	}
	maxDrift, err := time.ParseDuration(rt.cfg.Audit.TimeMaxDrift)
	if err != nil {
		return err
	}
	clock, err := securityaudit.NewClock(securityaudit.ClockOptions{
		ReferencePath: rt.cfg.Audit.TimeReferencePath, MaxSampleAge: maxSampleAge,
		MaxClockDrift: maxDrift, RequireSynchronized: rt.cfg.Audit.RequireSynchronizedTime,
	})
	if err != nil {
		return err
	}
	signer, _, err := rt.readSigner(command.Context(), rt.cfg.Audit.SigningKey)
	if err != nil {
		return fmt.Errorf("initialize security audit signer: %w", err)
	}
	writer, err := securityaudit.OpenWriter(command.Context(), securityaudit.Options{
		Path: rt.cfg.Audit.Path, CheckpointPath: rt.cfg.Audit.CheckpointPath,
		MaxBytes: rt.cfg.Audit.MaxBytes, Retention: retention, Signer: signer, Clock: clock,
	})
	if err != nil {
		return fmt.Errorf("initialize security audit trail: %w", err)
	}
	rt.auditor = writer
	rt.auditActor = localAuditActor()
	rt.auditRequestID = newAuditRequestID()
	if _, err := rt.auditor.Record(command.Context(), securityaudit.Draft{
		Actor: rt.auditActor, Action: "audit.writer.open", Object: rt.cfg.Audit.Path,
		Result: "success", RequestID: rt.auditRequestID, Source: "cli",
		Context: map[string]string{"command": command.CommandPath()},
	}); err != nil {
		return fmt.Errorf("record security audit startup: %w", err)
	}
	return nil
}

func (rt *runtimeConfig) auditRecord(ctx context.Context, draft securityaudit.Draft) error {
	if rt.auditor == nil {
		return nil
	}
	if draft.Actor == "" {
		draft.Actor = rt.auditActor
	}
	if len(draft.Roles) == 0 {
		draft.Roles = append([]string(nil), rt.auditRoles...)
	}
	if draft.PolicyVersion == 0 {
		draft.PolicyVersion = rt.auditPolicy
	}
	if draft.RequestID == "" {
		draft.RequestID = rt.auditRequestID
	}
	_, err := rt.auditor.Record(ctx, draft)
	return err
}

func wrapAuditedCommandRuns(root *cobra.Command, rt *runtimeConfig) {
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		if commandAuditAction(command) != "" {
			if oldRunE := command.RunE; oldRunE != nil {
				command.RunE = func(cmd *cobra.Command, args []string) error {
					err := oldRunE(cmd, args)
					auditErr := rt.recordCommandOutcome(cmd, err)
					combined := errors.Join(err, auditErr)
					if combined != nil {
						_ = rt.close()
					}
					return combined
				}
			} else if oldRun := command.Run; oldRun != nil {
				command.Run = nil
				command.RunE = func(cmd *cobra.Command, args []string) error {
					oldRun(cmd, args)
					err := rt.recordCommandOutcome(cmd, nil)
					if err != nil {
						_ = rt.close()
					}
					return err
				}
			}
		}
		for _, child := range command.Commands() {
			walk(child)
		}
	}
	walk(root)
}

func (rt *runtimeConfig) recordCommandOutcome(command *cobra.Command, commandErr error) error {
	if rt.auditor == nil {
		return nil
	}
	result := "success"
	contextValues := make(map[string]string)
	if permission := requiredPermission(command); permission != "" {
		contextValues["permission"] = string(permission)
	}
	if commandAuditAction(command) == "security.policy.recover" {
		contextValues["emergency"] = "true"
		contextValues["emergency_reason_digest"] = auditReasonDigest(strings.TrimSpace(os.Getenv(adminEmergencyReasonEnv)))
	}
	if commandErr != nil {
		result = "failure"
		contextValues["error_code"] = string(trusterr.CodeOf(commandErr))
	}
	if err := rt.auditRecord(command.Context(), securityaudit.Draft{
		Action: commandAuditAction(command), Object: command.CommandPath(), Result: result,
		Source: "cli", Context: contextValues,
	}); err != nil {
		return fmt.Errorf("record privileged command outcome: %w", err)
	}
	return nil
}

func requireAuditAction(command *cobra.Command, action string) *cobra.Command {
	if command.Annotations == nil {
		command.Annotations = make(map[string]string)
	}
	command.Annotations[auditActionAnnotation] = action
	return command
}

func commandAuditAction(command *cobra.Command) string {
	if command != nil && command.Annotations != nil {
		if action := strings.TrimSpace(command.Annotations[auditActionAnnotation]); action != "" {
			return action
		}
	}
	switch requiredPermission(command) {
	case adminauth.PermissionSystemRead:
		return "system.read"
	case adminauth.PermissionSystemConfigure:
		return "system.configuration"
	case adminauth.PermissionSystemOperate:
		return "system.operation"
	case adminauth.PermissionSecurityPolicyRead:
		return "security.policy.read"
	case adminauth.PermissionSecurityPolicyWrite:
		return "security.policy.update"
	case adminauth.PermissionAuditRead:
		return "audit.read"
	case adminauth.PermissionAuditExport:
		return "audit.export"
	case adminauth.PermissionKeyRead:
		return "key.read"
	case adminauth.PermissionKeyManage:
		return "key.lifecycle"
	case adminauth.PermissionBackupRead:
		return "backup.read"
	case adminauth.PermissionBackupCreate:
		return "backup.create"
	case adminauth.PermissionBackupRestore:
		return "backup.restore"
	case adminauth.PermissionAnchorRead:
		return "anchor.read"
	case adminauth.PermissionAnchorManage:
		return "anchor.configuration"
	case adminauth.PermissionTrustRead:
		return "trust.read"
	case adminauth.PermissionTrustManage:
		return "trust.configuration"
	case adminauth.PermissionSessionManage:
		return "session.lifecycle"
	default:
		return ""
	}
}

func localAuditActor() string {
	if actor := strings.TrimSpace(os.Getenv(adminActorEnv)); actor != "" {
		return actor
	}
	for _, name := range []string{"USER", "USERNAME", "LOGNAME"} {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return "os:" + value
		}
	}
	return "os:unknown"
}

func newAuditRequestID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return fmt.Sprintf("pid-%d-%d", os.Getpid(), time.Now().UnixNano())
	}
	return hex.EncodeToString(value[:])
}

func auditReasonDigest(reason string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(reason)))
	return hex.EncodeToString(digest[:])
}

func principalAuditRoles(principal adminauth.Principal) []string {
	roles := make([]string, len(principal.Roles))
	for index, role := range principal.Roles {
		roles[index] = string(role)
	}
	return roles
}
