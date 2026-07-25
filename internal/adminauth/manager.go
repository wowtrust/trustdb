package adminauth

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUnauthenticated  = errors.New("adminauth: unauthenticated")
	ErrPermissionDenied = errors.New("adminauth: permission denied")
	ErrPolicyChanged    = errors.New("adminauth: policy changed")
)

type AuthMethod string

const (
	AuthMethodLocal AuthMethod = "local-password"
	AuthMethodMTLS  AuthMethod = "mtls-spki"
	AuthMethodOIDC  AuthMethod = "oidc"
)

type Principal struct {
	AccountID     string       `json:"account_id"`
	Username      string       `json:"username"`
	Roles         []Role       `json:"roles"`
	Permissions   []Permission `json:"permissions"`
	AuthMethod    AuthMethod   `json:"auth_method"`
	PolicyVersion uint64       `json:"policy_version"`
	PolicyDigest  string       `json:"policy_digest"`
	SessionEpoch  uint64       `json:"session_epoch"`
	Emergency     bool         `json:"emergency,omitempty"`
	NotAfter      string       `json:"not_after,omitempty"`
	MFARequired   bool         `json:"mfa_required,omitempty"`
}

type Manager struct {
	mu     sync.RWMutex
	policy Policy
	digest string
}

func NewManager(policy Policy, now time.Time) (*Manager, error) {
	if err := policy.Validate(now); err != nil {
		return nil, err
	}
	digest, err := policy.Digest()
	if err != nil {
		return nil, err
	}
	return &Manager{policy: policy.Clone(), digest: digest}, nil
}

func (m *Manager) Snapshot() (Policy, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.policy.Clone(), m.digest
}

func (m *Manager) Replace(policy Policy, now time.Time) error {
	if err := policy.Validate(now); err != nil {
		return err
	}
	digest, err := policy.Digest()
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.policy = policy.Clone()
	m.digest = digest
	m.mu.Unlock()
	return nil
}

func (m *Manager) AuthenticateLocal(username, password string, now time.Time) (Principal, error) {
	m.mu.RLock()
	policy, digest := m.policy.Clone(), m.digest
	m.mu.RUnlock()
	account, found := findAccountByUsername(policy.Accounts, strings.TrimSpace(username))
	if !found || account.PasswordHash == "" || !account.active(now) {
		_ = bcrypt.CompareHashAndPassword([]byte(dummyPasswordHash), []byte(password))
		return Principal{}, ErrUnauthenticated
	}
	if err := bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)); err != nil {
		return Principal{}, ErrUnauthenticated
	}
	return principalFor(account, policy.Version, digest, AuthMethodLocal)
}

func (m *Manager) AuthenticateMTLS(certificate *x509.Certificate, now time.Time) (Principal, error) {
	if certificate == nil || len(certificate.RawSubjectPublicKeyInfo) == 0 {
		return Principal{}, ErrUnauthenticated
	}
	digestBytes := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(digestBytes[:])
	m.mu.RLock()
	policy, digest := m.policy.Clone(), m.digest
	m.mu.RUnlock()
	for _, account := range policy.Accounts {
		if account.active(now) && containsSortedString(account.MTLSSPKISHA256, pin) {
			return principalFor(account, policy.Version, digest, AuthMethodMTLS)
		}
	}
	return Principal{}, ErrUnauthenticated
}

func (m *Manager) AuthenticateOIDC(issuer, subject string, now time.Time) (Principal, error) {
	m.mu.RLock()
	policy, digest := m.policy.Clone(), m.digest
	m.mu.RUnlock()
	target := ExternalSubject{Issuer: issuer, Subject: subject}
	for _, account := range policy.Accounts {
		if account.active(now) && containsSortedSubject(account.OIDCSubjects, target) {
			return principalFor(account, policy.Version, digest, AuthMethodOIDC)
		}
	}
	return Principal{}, ErrUnauthenticated
}

func (m *Manager) Authorize(principal Principal, permission Permission, now time.Time) (Principal, error) {
	current, err := m.ValidatePrincipal(principal, now)
	if err != nil {
		return Principal{}, err
	}
	if !HasPermission(current.Roles, permission) {
		return Principal{}, fmt.Errorf("%w: %s", ErrPermissionDenied, permission)
	}
	return current, nil
}

func (m *Manager) ValidatePrincipal(principal Principal, now time.Time) (Principal, error) {
	m.mu.RLock()
	policy, digest := m.policy.Clone(), m.digest
	m.mu.RUnlock()
	if principal.PolicyDigest != digest || principal.PolicyVersion != policy.Version {
		return Principal{}, ErrPolicyChanged
	}
	account, found := findAccountByID(policy.Accounts, principal.AccountID)
	if !found || !account.active(now) || account.SessionEpoch != principal.SessionEpoch || !reflect.DeepEqual(account.Roles, principal.Roles) {
		return Principal{}, ErrUnauthenticated
	}
	return principalFor(account, policy.Version, digest, principal.AuthMethod)
}

func ValidateOnlineUpdate(actor Principal, current, next Policy, now time.Time) error {
	if err := current.Validate(now); err != nil {
		return fmt.Errorf("adminauth: current policy: %w", err)
	}
	if err := next.Validate(now); err != nil {
		return fmt.Errorf("adminauth: replacement policy: %w", err)
	}
	currentDigest, _ := current.Digest()
	if actor.PolicyDigest != currentDigest || actor.PolicyVersion != current.Version || !HasPermission(actor.Roles, PermissionSecurityPolicyWrite) {
		return ErrPermissionDenied
	}
	if next.Version != current.Version+1 {
		return errors.New("adminauth: replacement policy version must advance by exactly one")
	}
	oldActor, foundOld := findAccountByID(current.Accounts, actor.AccountID)
	newActor, foundNew := findAccountByID(next.Accounts, actor.AccountID)
	if !foundOld || !foundNew || !reflect.DeepEqual(oldActor, newActor) {
		return errors.New("adminauth: online policy writers cannot modify their own account")
	}
	if !reflect.DeepEqual(separationCustodyAccounts(current.Accounts), separationCustodyAccounts(next.Accounts)) {
		return errors.New("adminauth: system and audit administrator custody may be changed only through offline recovery")
	}
	if !reflect.DeepEqual(emergencyAccounts(current.Accounts), emergencyAccounts(next.Accounts)) {
		return errors.New("adminauth: emergency accounts may be changed only through offline recovery")
	}
	return nil
}

func separationCustodyAccounts(accounts []Account) []Account {
	out := make([]Account, 0)
	for _, account := range accounts {
		if account.hasRole(RoleSystemAdmin) || account.hasRole(RoleAuditAdmin) {
			out = append(out, account.clone())
		}
	}
	return out
}

func principalFor(account Account, version uint64, digest string, method AuthMethod) (Principal, error) {
	permissions, err := PermissionsForRoles(account.Roles)
	if err != nil {
		return Principal{}, err
	}
	return Principal{
		AccountID: account.ID, Username: account.Username, Roles: append([]Role(nil), account.Roles...),
		Permissions: permissions, AuthMethod: method, PolicyVersion: version, PolicyDigest: digest,
		SessionEpoch: account.SessionEpoch, Emergency: account.Emergency, NotAfter: account.NotAfter,
		MFARequired: account.MFARequired,
	}, nil
}

func findAccountByUsername(accounts []Account, username string) (Account, bool) {
	for _, account := range accounts {
		if strings.EqualFold(account.Username, username) {
			return account.clone(), true
		}
	}
	return Account{}, false
}

func findAccountByID(accounts []Account, id string) (Account, bool) {
	index := sort.Search(len(accounts), func(i int) bool { return accounts[i].ID >= id })
	if index < len(accounts) && accounts[index].ID == id {
		return accounts[index].clone(), true
	}
	return Account{}, false
}

func containsSortedString(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func containsSortedSubject(values []ExternalSubject, target ExternalSubject) bool {
	targetKey := target.Issuer + "\x00" + target.Subject
	index := sort.Search(len(values), func(i int) bool {
		return values[i].Issuer+"\x00"+values[i].Subject >= targetKey
	})
	return index < len(values) && values[index] == target
}

func emergencyAccounts(accounts []Account) []Account {
	out := make([]Account, 0)
	for _, account := range accounts {
		if account.Emergency {
			out = append(out, account.clone())
		}
	}
	return out
}

const dummyPasswordHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOeWlqT7/hZV5cDgYE.KqPzQ6x4c4O8yK"
