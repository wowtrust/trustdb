package sproof

import (
	"bytes"
	"fmt"
	"time"

	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/keystore"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

// IdentityTrust is verifier-local policy. Nothing carried by a .sproof file
// is copied into this structure or promoted to a trust root.
type IdentityTrust struct {
	ClientPublicKeys         []trustcrypto.PublicKeyDescriptor
	ServerPublicKeys         []trustcrypto.PublicKeyDescriptor
	ClientCertificateRoots   [][]byte
	ServerCertificateRoots   [][]byte
	RegistryPublicKey        trustcrypto.PublicKeyDescriptor
	RequireEvidence          bool
	RequireCertificateStatus bool
}

// IdentityReport records the independently recomputed identity stages. It is
// diagnostic output only; callers still derive L1-L5 from proof verification.
type IdentityReport struct {
	EvidenceCount               int `json:"evidence_count"`
	PublicKeyBindingsVerified   int `json:"public_key_bindings_verified"`
	LifecycleBindingsVerified   int `json:"lifecycle_bindings_verified"`
	CertificateChainsVerified   int `json:"certificate_chains_verified"`
	CertificateStatusesVerified int `json:"certificate_statuses_verified"`
}

// VerifyIdentityEvidence binds every carried descriptor and status object to
// verifier-local trust. It performs no network or provider calls.
func VerifyIdentityEvidence(proof model.SingleProof, trust IdentityTrust) (IdentityReport, error) {
	if err := validateContainer(proof); err != nil {
		return IdentityReport{}, err
	}
	if err := validateIdentityEvidenceDetails(proof); err != nil {
		return IdentityReport{}, err
	}
	required := requiredIdentityKeys(proof)
	evidenceByKey := make(map[string]model.ProofIdentityEvidence, len(proof.IdentityEvidence))
	for index := range proof.IdentityEvidence {
		evidence := proof.IdentityEvidence[index]
		evidenceByKey[identityEvidenceKey(evidence.Role, evidence.KeyID)] = evidence
	}
	if trust.RequireEvidence {
		for key := range required {
			if _, ok := evidenceByKey[key]; !ok {
				return IdentityReport{}, fmt.Errorf("sproof: required identity evidence %q is missing", key)
			}
		}
	}

	report := IdentityReport{EvidenceCount: len(proof.IdentityEvidence)}
	for index := range proof.IdentityEvidence {
		evidence := proof.IdentityEvidence[index]
		descriptor, err := keydescriptor.Unmarshal(evidence.KeyDescriptor)
		if err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] descriptor: %w", index, err)
		}
		publicKey, err := descriptor.PublicKeyDescriptor()
		if err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] public key: %w", index, err)
		}
		trustedKeys := trust.ServerPublicKeys
		roots := trust.ServerCertificateRoots
		if evidence.Role == model.ProofIdentityRoleClient {
			trustedKeys = trust.ClientPublicKeys
			roots = trust.ClientCertificateRoots
		}
		if err := requireTrustedPublicKey(publicKey, trustedKeys); err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d]: %w", index, err)
		}
		report.PublicKeyBindingsVerified++

		if len(evidence.RegistryV2) != 0 {
			registry, err := keystore.OpenEvidence(evidence.RegistryV2, trust.RegistryPublicKey)
			if err != nil {
				return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] registry lifecycle: %w", index, err)
			}
			claim := proof.ProofBundle.SignedClaim.Claim
			lifecycleKey, err := registry.LookupClientKeyAt(
				claim.TenantID,
				claim.ClientID,
				evidence.KeyID,
				time.Unix(0, claim.ProducedAtUnixN).UTC(),
			)
			if err != nil {
				return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] signing-time lifecycle: %w", index, err)
			}
			if lifecycleKey.CryptoSuite != publicKey.Suite ||
				lifecycleKey.KeyID != publicKey.KeyID ||
				lifecycleKey.Alg != publicKey.Algorithm ||
				lifecycleKey.PublicKeyEncoding != publicKey.Encoding ||
				!bytes.Equal(lifecycleKey.PublicKey, publicKey.Bytes) {
				return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] registry key does not match the public descriptor", index)
			}
			report.LifecycleBindingsVerified++
		}

		if len(descriptor.CertificateChain) == 0 {
			if trust.RequireCertificateStatus {
				return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] certificate chain and status are required by local policy", index)
			}
			continue
		}
		signingTimes, err := identitySigningTimes(proof, evidence)
		if err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d]: %w", index, err)
		}
		certificates, trustedRoots, err := verifyCertificateChain(
			proof.CryptoSuite,
			descriptor.CertificateChain,
			roots,
			signingTimes,
		)
		if err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] certificate chain: %w", index, err)
		}
		report.CertificateChainsVerified++
		verifiedStatuses, err := verifyCertificateStatuses(
			proof.CryptoSuite,
			certificates,
			trustedRoots,
			evidence.CertificateStatuses,
			signingTimes,
			trust.RequireCertificateStatus,
		)
		if err != nil {
			return IdentityReport{}, fmt.Errorf("sproof: identity_evidence[%d] certificate status: %w", index, err)
		}
		report.CertificateStatusesVerified += verifiedStatuses
	}
	return report, nil
}

func requiredIdentityKeys(proof model.SingleProof) map[string]struct{} {
	required := map[string]struct{}{
		identityEvidenceKey(model.ProofIdentityRoleClient, proof.ProofBundle.SignedClaim.Signature.KeyID):      {},
		identityEvidenceKey(model.ProofIdentityRoleServer, proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID):  {},
		identityEvidenceKey(model.ProofIdentityRoleServer, proof.ProofBundle.CommittedReceipt.ServerSig.KeyID): {},
	}
	if proof.GlobalProof != nil {
		required[identityEvidenceKey(model.ProofIdentityRoleServer, proof.GlobalProof.STH.Signature.KeyID)] = struct{}{}
	}
	delete(required, identityEvidenceKey(model.ProofIdentityRoleClient, ""))
	delete(required, identityEvidenceKey(model.ProofIdentityRoleServer, ""))
	return required
}

func identityEvidenceKey(role, keyID string) string {
	return role + "\x00" + keyID
}

func requireTrustedPublicKey(actual trustcrypto.PublicKeyDescriptor, trusted []trustcrypto.PublicKeyDescriptor) error {
	var matches int
	for index := range trusted {
		candidate := trusted[index]
		if candidate.KeyID != actual.KeyID {
			continue
		}
		if candidate.Suite == actual.Suite &&
			candidate.Algorithm == actual.Algorithm &&
			candidate.Encoding == actual.Encoding &&
			bytes.Equal(candidate.Bytes, actual.Bytes) {
			matches++
		}
	}
	if matches != 1 {
		return fmt.Errorf("public descriptor has %d exact verifier-local trust bindings, want 1", matches)
	}
	return nil
}

func identitySigningTimes(proof model.SingleProof, evidence model.ProofIdentityEvidence) ([]time.Time, error) {
	var unixNanos []int64
	switch evidence.Role {
	case model.ProofIdentityRoleClient:
		unixNanos = append(unixNanos, proof.ProofBundle.SignedClaim.Claim.ProducedAtUnixN)
	case model.ProofIdentityRoleServer:
		if proof.ProofBundle.AcceptedReceipt.ServerSig.KeyID == evidence.KeyID {
			unixNanos = append(unixNanos, proof.ProofBundle.AcceptedReceipt.ReceivedAtUnixN)
		}
		if proof.ProofBundle.CommittedReceipt.ServerSig.KeyID == evidence.KeyID {
			unixNanos = append(unixNanos, proof.ProofBundle.CommittedReceipt.ClosedAtUnixN)
		}
		if proof.GlobalProof != nil && proof.GlobalProof.STH.Signature.KeyID == evidence.KeyID {
			unixNanos = append(unixNanos, proof.GlobalProof.STH.TimestampUnixN)
		}
	}
	seen := make(map[int64]struct{}, len(unixNanos))
	times := make([]time.Time, 0, len(unixNanos))
	for _, unixNano := range unixNanos {
		if unixNano <= 0 {
			return nil, fmt.Errorf("signature time for key %q is missing", evidence.KeyID)
		}
		if _, duplicate := seen[unixNano]; duplicate {
			continue
		}
		seen[unixNano] = struct{}{}
		times = append(times, time.Unix(0, unixNano).UTC())
	}
	if len(times) == 0 {
		return nil, fmt.Errorf("identity key %q is not used by a timestamped signature", evidence.KeyID)
	}
	return times, nil
}

func verifyCertificateChain(
	suiteID cryptosuite.ID,
	chainDER [][]byte,
	rootDER [][]byte,
	signingTimes []time.Time,
) ([]*smx509.Certificate, []*smx509.Certificate, error) {
	if len(chainDER) == 0 {
		return nil, nil, fmt.Errorf("certificate chain is empty")
	}
	if len(rootDER) == 0 {
		return nil, nil, fmt.Errorf("verifier-local certificate roots are required")
	}
	chain := make([]*smx509.Certificate, len(chainDER))
	for index := range chainDER {
		certificate, err := smx509.ParseCertificate(chainDER[index])
		if err != nil || !bytes.Equal(certificate.Raw, chainDER[index]) {
			return nil, nil, fmt.Errorf("certificate %d is invalid DER", index)
		}
		chain[index] = certificate
	}
	roots := make([]*smx509.Certificate, len(rootDER))
	rootPool := smx509.NewCertPool()
	for index := range rootDER {
		root, err := smx509.ParseCertificate(rootDER[index])
		if err != nil || !bytes.Equal(root.Raw, rootDER[index]) {
			return nil, nil, fmt.Errorf("local root %d is invalid DER", index)
		}
		if !root.IsCA || root.CheckSignatureFrom(root) != nil {
			return nil, nil, fmt.Errorf("local root %d is not a self-signed CA", index)
		}
		if err := requireCertificateAlgorithm(suiteID, root.SignatureAlgorithm); err != nil {
			return nil, nil, fmt.Errorf("local root %d: %w", index, err)
		}
		roots[index] = root
		rootPool.AddCert(root)
	}
	intermediates := smx509.NewCertPool()
	for index := 1; index < len(chain); index++ {
		intermediates.AddCert(chain[index])
	}
	for _, signingTime := range signingTimes {
		if _, err := chain[0].Verify(smx509.VerifyOptions{
			Roots:         rootPool,
			Intermediates: intermediates,
			CurrentTime:   signingTime,
			KeyUsages:     []smx509.ExtKeyUsage{smx509.ExtKeyUsageAny},
		}); err != nil {
			return nil, nil, fmt.Errorf("verify at %s: %w", signingTime.Format(time.RFC3339Nano), err)
		}
	}
	return chain, roots, nil
}

func verifyCertificateStatuses(
	suiteID cryptosuite.ID,
	chain []*smx509.Certificate,
	roots []*smx509.Certificate,
	statuses []model.CertificateStatusEvidence,
	signingTimes []time.Time,
	required bool,
) (int, error) {
	if len(statuses) == 0 {
		if required {
			return 0, fmt.Errorf("signed certificate status material is required")
		}
		return 0, nil
	}
	statusByIssuer := make(map[string]model.CertificateStatusEvidence, len(statuses))
	for index := range statuses {
		statusByIssuer[string(statuses[index].IssuerFingerprint)] = statuses[index]
	}
	issuers := append(append([]*smx509.Certificate(nil), chain[1:]...), roots...)
	used := make(map[string]struct{}, len(statuses))
	verified := 0
	for _, certificate := range chain {
		if certificateIsTrustedRoot(certificate, roots) {
			continue
		}
		issuer, err := findCertificateIssuer(certificate, issuers)
		if err != nil {
			return 0, err
		}
		fingerprint, err := certificateFingerprint(suiteID, issuer)
		if err != nil {
			return 0, err
		}
		status, ok := statusByIssuer[string(fingerprint)]
		if !ok {
			return 0, fmt.Errorf("missing CRL for certificate issuer")
		}
		if err := verifyCRL(suiteID, status.Status, issuer, certificate, signingTimes); err != nil {
			return 0, err
		}
		used[string(fingerprint)] = struct{}{}
		verified++
	}
	if len(used) != len(statuses) {
		return 0, fmt.Errorf("certificate status contains an unreferenced issuer")
	}
	return verified, nil
}

func certificateIsTrustedRoot(certificate *smx509.Certificate, roots []*smx509.Certificate) bool {
	for _, root := range roots {
		if bytes.Equal(certificate.Raw, root.Raw) {
			return true
		}
	}
	return false
}

func findCertificateIssuer(certificate *smx509.Certificate, candidates []*smx509.Certificate) (*smx509.Certificate, error) {
	var issuer *smx509.Certificate
	for _, candidate := range candidates {
		if !bytes.Equal(certificate.RawIssuer, candidate.RawSubject) ||
			certificate.CheckSignatureFrom(candidate) != nil {
			continue
		}
		if len(certificate.AuthorityKeyId) != 0 &&
			!bytes.Equal(certificate.AuthorityKeyId, candidate.SubjectKeyId) {
			continue
		}
		if issuer != nil && !bytes.Equal(issuer.Raw, candidate.Raw) {
			return nil, fmt.Errorf("certificate issuer is ambiguous")
		}
		issuer = candidate
	}
	if issuer == nil {
		return nil, fmt.Errorf("certificate issuer is not present in local trust")
	}
	return issuer, nil
}

func certificateFingerprint(suiteID cryptosuite.ID, certificate *smx509.Certificate) ([]byte, error) {
	suite, err := cryptosuite.RequireAvailable(suiteID)
	if err != nil {
		return nil, err
	}
	return trustcrypto.HashBytesForSuite(suiteID, suite.KeyFingerprintHash.Algorithm, certificate.Raw)
}

func verifyCRL(
	suiteID cryptosuite.ID,
	raw []byte,
	issuer, certificate *smx509.Certificate,
	signingTimes []time.Time,
) error {
	crl, err := smx509.ParseRevocationList(raw)
	if err != nil || !bytes.Equal(crl.Raw, raw) {
		return fmt.Errorf("CRL is invalid DER")
	}
	if err := requireCertificateAlgorithm(suiteID, crl.SignatureAlgorithm); err != nil {
		return fmt.Errorf("CRL: %w", err)
	}
	if len(crl.AuthorityKeyId) == 0 ||
		len(issuer.SubjectKeyId) == 0 ||
		!bytes.Equal(crl.AuthorityKeyId, issuer.SubjectKeyId) {
		return fmt.Errorf("CRL authority key identifier does not match its issuer")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("CRL signature: %w", err)
	}
	if crl.NextUpdate.IsZero() {
		return fmt.Errorf("CRL nextUpdate is required")
	}
	if err := validateCRLEntries(crl); err != nil {
		return err
	}
	for _, signingTime := range signingTimes {
		if signingTime.Before(crl.ThisUpdate) || !signingTime.Before(crl.NextUpdate) {
			return fmt.Errorf("CRL does not cover signature time %s", signingTime.Format(time.RFC3339Nano))
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(certificate.SerialNumber) == 0 &&
				(entry.RevocationTime.IsZero() || !signingTime.Before(entry.RevocationTime)) {
				return fmt.Errorf("certificate was revoked at signature time")
			}
		}
	}
	return nil
}

func validateCRLEntries(crl *smx509.RevocationList) error {
	seen := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 {
			return fmt.Errorf("CRL contains an invalid certificate serial")
		}
		key := entry.SerialNumber.Text(16)
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("CRL contains a duplicate certificate serial")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func requireCertificateAlgorithm(suiteID cryptosuite.ID, algorithm smx509.SignatureAlgorithm) error {
	switch suiteID {
	case cryptosuite.INTLV1:
		if algorithm != smx509.PureEd25519 {
			return fmt.Errorf("signature algorithm is not Ed25519")
		}
	case cryptosuite.CNSMV1:
		if algorithm != smx509.SM2WithSM3 {
			return fmt.Errorf("signature algorithm is not SM2-with-SM3")
		}
	default:
		return fmt.Errorf("certificate suite is unsupported")
	}
	return nil
}
