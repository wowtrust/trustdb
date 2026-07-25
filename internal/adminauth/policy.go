package adminauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	PolicySchema       = "trustdb.admin-policy.v1"
	MaxPolicyBytes     = 4 << 20
	MaxAccounts        = 256
	MaxEmergencyAccess = 24 * time.Hour
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Policy struct {
	SchemaVersion string    `json:"schema_version"`
	Version       uint64    `json:"version"`
	Accounts      []Account `json:"accounts"`
}

type Account struct {
	ID             string            `json:"id"`
	Username       string            `json:"username"`
	PasswordHash   string            `json:"password_hash,omitempty"`
	Roles          []Role            `json:"roles"`
	MTLSSPKISHA256 []string          `json:"mtls_spki_sha256,omitempty"`
	OIDCSubjects   []ExternalSubject `json:"oidc_subjects,omitempty"`
	MFARequired    bool              `json:"mfa_required,omitempty"`
	Disabled       bool              `json:"disabled,omitempty"`
	Emergency      bool              `json:"emergency,omitempty"`
	NotBefore      string            `json:"not_before,omitempty"`
	NotAfter       string            `json:"not_after,omitempty"`
	SessionEpoch   uint64            `json:"session_epoch"`
	Description    string            `json:"description,omitempty"`
}

type ExternalSubject struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

func ParsePolicy(data []byte, now time.Time) (Policy, error) {
	if len(data) == 0 || len(data) > MaxPolicyBytes {
		return Policy{}, fmt.Errorf("adminauth: policy size must be between 1 and %d bytes", MaxPolicyBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var policy Policy
	if err := decoder.Decode(&policy); err != nil {
		return Policy{}, fmt.Errorf("adminauth: decode policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		return Policy{}, errors.New("adminauth: policy has trailing JSON data")
	} else if !errors.Is(err, io.EOF) {
		return Policy{}, fmt.Errorf("adminauth: decode policy trailer: %w", err)
	}
	if err := policy.Validate(now); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

func (p Policy) Validate(now time.Time) error {
	if p.SchemaVersion != PolicySchema || p.Version == 0 {
		return fmt.Errorf("adminauth: policy must use %s with a positive version", PolicySchema)
	}
	if len(p.Accounts) < 3 || len(p.Accounts) > MaxAccounts {
		return fmt.Errorf("adminauth: policy accounts must contain 3..%d entries", MaxAccounts)
	}
	seenIDs := make(map[string]struct{}, len(p.Accounts))
	seenUsers := make(map[string]struct{}, len(p.Accounts))
	seenMTLS := make(map[string]struct{})
	seenOIDC := make(map[string]struct{})
	activeSeparation := map[Role]int{
		RoleSystemAdmin: 0, RoleSecurityAdmin: 0, RoleAuditAdmin: 0,
	}
	previousID := ""
	for index, account := range p.Accounts {
		if err := account.validate(now); err != nil {
			return fmt.Errorf("adminauth: account %d: %w", index, err)
		}
		if previousID != "" && account.ID <= previousID {
			return errors.New("adminauth: accounts must be sorted by id and unique")
		}
		previousID = account.ID
		if _, exists := seenIDs[account.ID]; exists {
			return fmt.Errorf("adminauth: duplicate account id %q", account.ID)
		}
		seenIDs[account.ID] = struct{}{}
		userKey := strings.ToLower(account.Username)
		if _, exists := seenUsers[userKey]; exists {
			return fmt.Errorf("adminauth: duplicate username %q", account.Username)
		}
		seenUsers[userKey] = struct{}{}
		for _, pin := range account.MTLSSPKISHA256 {
			if _, exists := seenMTLS[pin]; exists {
				return fmt.Errorf("adminauth: duplicate mTLS SPKI pin %q", pin)
			}
			seenMTLS[pin] = struct{}{}
		}
		for _, subject := range account.OIDCSubjects {
			key := subject.Issuer + "\x00" + subject.Subject
			if _, exists := seenOIDC[key]; exists {
				return fmt.Errorf("adminauth: duplicate OIDC subject %q", subject.Subject)
			}
			seenOIDC[key] = struct{}{}
		}
		if account.active(now) && !account.Emergency {
			for role := range activeSeparation {
				if account.hasRole(role) {
					activeSeparation[role]++
				}
			}
		}
	}
	for role, count := range activeSeparation {
		if count == 0 {
			return fmt.Errorf("adminauth: policy requires an active non-emergency %s account", role)
		}
	}
	return nil
}

func (a Account) validate(now time.Time) error {
	if !identifierPattern.MatchString(a.ID) || !identifierPattern.MatchString(a.Username) {
		return errors.New("id and username must be canonical identifiers")
	}
	if a.SessionEpoch == 0 {
		return errors.New("session_epoch must be positive")
	}
	if len(a.Roles) == 0 || !sortedUniqueRoles(a.Roles) {
		return errors.New("roles must be non-empty, sorted, and unique")
	}
	for _, role := range a.Roles {
		if !KnownRole(role) {
			return fmt.Errorf("unknown role %q", role)
		}
	}
	separationRoles := 0
	for _, role := range []Role{RoleSystemAdmin, RoleSecurityAdmin, RoleAuditAdmin} {
		if a.hasRole(role) {
			separationRoles++
		}
	}
	if !a.Emergency && separationRoles > 1 {
		return errors.New("system, security, and audit administration roles must belong to separate ordinary accounts")
	}
	if a.Emergency {
		if len(a.Roles) != 1 || a.Roles[0] != RoleEmergencyAdmin {
			return errors.New("emergency accounts must have only emergency-admin")
		}
	} else if a.hasRole(RoleEmergencyAdmin) {
		return errors.New("emergency-admin requires emergency=true")
	}
	if a.PasswordHash != "" {
		if _, err := bcrypt.Cost([]byte(a.PasswordHash)); err != nil {
			return errors.New("password_hash is not bcrypt")
		}
	}
	if !sortedUniqueStrings(a.MTLSSPKISHA256) {
		return errors.New("mTLS SPKI pins must be sorted and unique")
	}
	for _, pin := range a.MTLSSPKISHA256 {
		if len(pin) != sha256.Size*2 || strings.ToLower(pin) != pin {
			return errors.New("mTLS SPKI pins must be lowercase SHA-256 hex")
		}
		if _, err := hex.DecodeString(pin); err != nil {
			return errors.New("mTLS SPKI pin is invalid hex")
		}
	}
	if !sortedUniqueSubjects(a.OIDCSubjects) {
		return errors.New("OIDC subjects must be sorted and unique")
	}
	for _, subject := range a.OIDCSubjects {
		issuer, err := url.Parse(subject.Issuer)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" || subject.Subject == "" || len(subject.Subject) > 512 {
			return errors.New("OIDC subject requires an https issuer and bounded subject")
		}
	}
	if a.PasswordHash == "" && len(a.MTLSSPKISHA256) == 0 && len(a.OIDCSubjects) == 0 {
		return errors.New("account requires at least one authentication binding")
	}
	notBefore, notAfter, err := a.validity()
	if err != nil {
		return err
	}
	if a.Emergency {
		if notAfter.IsZero() || notBefore.IsZero() || !notAfter.After(notBefore) || notAfter.Sub(notBefore) > MaxEmergencyAccess {
			return fmt.Errorf("emergency account validity must be positive and at most %s", MaxEmergencyAccess)
		}
	}
	_ = now
	return nil
}

func (a Account) validity() (time.Time, time.Time, error) {
	parse := func(name, value string) (time.Time, error) {
		if value == "" {
			return time.Time{}, nil
		}
		parsed, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return time.Time{}, fmt.Errorf("%s must be RFC3339 UTC time", name)
		}
		if parsed.Location() != time.UTC {
			return time.Time{}, fmt.Errorf("%s must use UTC", name)
		}
		return parsed, nil
	}
	notBefore, err := parse("not_before", a.NotBefore)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parse("not_after", a.NotAfter)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !notBefore.IsZero() && !notAfter.IsZero() && !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, errors.New("not_after must be after not_before")
	}
	return notBefore, notAfter, nil
}

func (a Account) active(now time.Time) bool {
	if a.Disabled {
		return false
	}
	notBefore, notAfter, err := a.validity()
	if err != nil {
		return false
	}
	if !notBefore.IsZero() && now.Before(notBefore) {
		return false
	}
	return notAfter.IsZero() || now.Before(notAfter)
}

func (a Account) hasRole(role Role) bool {
	index := sort.Search(len(a.Roles), func(i int) bool { return a.Roles[i] >= role })
	return index < len(a.Roles) && a.Roles[index] == role
}

func (p Policy) CanonicalBytes() ([]byte, error) {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func (p Policy) Digest() (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func (p Policy) Clone() Policy {
	out := p
	out.Accounts = make([]Account, len(p.Accounts))
	for i := range p.Accounts {
		out.Accounts[i] = p.Accounts[i].clone()
	}
	return out
}

func (a Account) clone() Account {
	a.Roles = append([]Role(nil), a.Roles...)
	a.MTLSSPKISHA256 = append([]string(nil), a.MTLSSPKISHA256...)
	a.OIDCSubjects = append([]ExternalSubject(nil), a.OIDCSubjects...)
	return a
}

func sortedUniqueRoles(values []Role) bool {
	for i := range values {
		if i > 0 && values[i-1] >= values[i] {
			return false
		}
	}
	return true
}

func sortedUniqueStrings(values []string) bool {
	for i := range values {
		if values[i] == "" || (i > 0 && values[i-1] >= values[i]) {
			return false
		}
	}
	return true
}

func sortedUniqueSubjects(values []ExternalSubject) bool {
	previous := ""
	for i, value := range values {
		key := value.Issuer + "\x00" + value.Subject
		if i > 0 && previous >= key {
			return false
		}
		previous = key
	}
	return true
}
