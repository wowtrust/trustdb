package adminauth

import (
	"fmt"
	"sort"
)

type Role string

const (
	RoleSystemAdmin     Role = "system-admin"
	RoleSecurityAdmin   Role = "security-admin"
	RoleAuditAdmin      Role = "audit-admin"
	RoleKeyOperator     Role = "key-operator"
	RoleBackupOperator  Role = "backup-operator"
	RoleAnchorGovernor  Role = "anchor-governor"
	RoleSupportReadOnly Role = "support-readonly"
	RoleEmergencyAdmin  Role = "emergency-admin"
)

type Permission string

const (
	PermissionSystemRead          Permission = "system.read"
	PermissionSystemConfigure     Permission = "system.configure"
	PermissionSystemOperate       Permission = "system.operate"
	PermissionSecurityPolicyRead  Permission = "security.policy.read"
	PermissionSecurityPolicyWrite Permission = "security.policy.write"
	PermissionAuditRead           Permission = "audit.read"
	PermissionAuditExport         Permission = "audit.export"
	PermissionKeyRead             Permission = "key.read"
	PermissionKeyManage           Permission = "key.manage"
	PermissionBackupRead          Permission = "backup.read"
	PermissionBackupCreate        Permission = "backup.create"
	PermissionBackupRestore       Permission = "backup.restore"
	PermissionAnchorRead          Permission = "anchor.read"
	PermissionAnchorManage        Permission = "anchor.manage"
	PermissionTrustRead           Permission = "trust.read"
	PermissionTrustManage         Permission = "trust.manage"
	PermissionSessionManage       Permission = "session.manage"
)

var rolePermissions = map[Role][]Permission{
	RoleSystemAdmin: {
		PermissionSystemRead, PermissionSystemConfigure, PermissionSystemOperate,
	},
	RoleSecurityAdmin: {
		PermissionSystemRead, PermissionSecurityPolicyRead, PermissionSecurityPolicyWrite,
		PermissionTrustRead, PermissionTrustManage, PermissionSessionManage,
	},
	RoleAuditAdmin: {
		PermissionSystemRead, PermissionSecurityPolicyRead, PermissionAuditRead, PermissionAuditExport,
	},
	RoleKeyOperator: {
		PermissionKeyRead, PermissionKeyManage,
	},
	RoleBackupOperator: {
		PermissionBackupRead, PermissionBackupCreate, PermissionBackupRestore,
	},
	RoleAnchorGovernor: {
		PermissionAnchorRead, PermissionAnchorManage, PermissionTrustRead,
	},
	RoleSupportReadOnly: {
		PermissionSystemRead, PermissionKeyRead, PermissionBackupRead, PermissionAnchorRead, PermissionTrustRead,
	},
	RoleEmergencyAdmin: {
		PermissionSystemRead, PermissionSystemConfigure, PermissionSystemOperate,
		PermissionSecurityPolicyRead, PermissionSecurityPolicyWrite,
		PermissionAuditRead, PermissionAuditExport,
		PermissionKeyRead, PermissionKeyManage,
		PermissionBackupRead, PermissionBackupCreate, PermissionBackupRestore,
		PermissionAnchorRead, PermissionAnchorManage,
		PermissionTrustRead, PermissionTrustManage, PermissionSessionManage,
	},
}

func KnownRole(role Role) bool {
	_, ok := rolePermissions[role]
	return ok
}

func PermissionsForRoles(roles []Role) ([]Permission, error) {
	set := make(map[Permission]struct{})
	for _, role := range roles {
		permissions, ok := rolePermissions[role]
		if !ok {
			return nil, fmt.Errorf("adminauth: unknown role %q", role)
		}
		for _, permission := range permissions {
			set[permission] = struct{}{}
		}
	}
	out := make([]Permission, 0, len(set))
	for permission := range set {
		out = append(out, permission)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func HasPermission(roles []Role, permission Permission) bool {
	for _, role := range roles {
		for _, granted := range rolePermissions[role] {
			if granted == permission {
				return true
			}
		}
	}
	return false
}
