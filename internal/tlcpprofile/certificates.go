package tlcpprofile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

type certificateSet struct {
	signingLeaf        *smx509.Certificate
	encryptionLeaf     *smx509.Certificate
	serverRoots        []*smx509.Certificate
	clientRoots        []*smx509.Certificate
	serverCertificates []*smx509.Certificate
	all                []*smx509.Certificate
}

func validatePublicTrust(profile Profile, now time.Time) (Report, error) {
	serverRoots, err := loadCABundle(profile.Certificates.ServerCAFile, now)
	if err != nil {
		return Report{}, fmt.Errorf("validate TLCP server CA: %w", err)
	}
	clientRoots, err := loadCABundle(profile.Certificates.ClientCAFile, now)
	if err != nil {
		return Report{}, fmt.Errorf("validate TLCP client CA: %w", err)
	}
	signingChain, err := loadEndpointChain(
		profile.Certificates.ServerSigningChainFile,
		serverRoots,
		profile.ServerName,
		now,
		signingCertificateRole,
	)
	if err != nil {
		return Report{}, fmt.Errorf("validate TLCP signing certificate: %w", err)
	}
	encryptionChain, err := loadEndpointChain(
		profile.Certificates.ServerEncryptionChainFile,
		serverRoots,
		profile.ServerName,
		now,
		encryptionCertificateRole,
	)
	if err != nil {
		return Report{}, fmt.Errorf("validate TLCP encryption certificate: %w", err)
	}
	if err := validateDualCertificateIdentity(signingChain[0], encryptionChain[0]); err != nil {
		return Report{}, err
	}
	set := certificateSet{
		signingLeaf: signingChain[0], encryptionLeaf: encryptionChain[0],
		serverRoots: serverRoots, clientRoots: clientRoots,
		serverCertificates: append(
			append([]*smx509.Certificate(nil), signingChain...),
			encryptionChain...,
		),
		all: append(append(append(
			append([]*smx509.Certificate(nil), signingChain...),
			encryptionChain...),
			serverRoots...),
			clientRoots...),
	}
	crls, err := loadAndValidateCRLs(profile.Revocation, set, now)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		SchemaVersion:               SchemaVersion,
		ProfileID:                   profile.ProfileID,
		ServerName:                  profile.ServerName,
		SigningCertificateSHA256:    certificateFingerprint(set.signingLeaf),
		EncryptionCertificateSHA256: certificateFingerprint(set.encryptionLeaf),
		SigningPublicKeySHA256:      publicKeyFingerprint(set.signingLeaf),
		EncryptionPublicKeySHA256:   publicKeyFingerprint(set.encryptionLeaf),
		ServerCASHA256:              certificateFingerprints(serverRoots),
		ClientCASHA256:              certificateFingerprints(clientRoots),
	}
	if report.SigningPublicKeySHA256 != profile.Certificates.SigningKey.PublicKeySHA256 {
		return Report{}, errors.New("TLCP signing key fingerprint does not match the signing certificate")
	}
	if report.EncryptionPublicKeySHA256 != profile.Certificates.EncryptionKey.PublicKeySHA256 {
		return Report{}, errors.New("TLCP encryption key fingerprint does not match the encryption certificate")
	}
	for _, certificate := range set.all {
		if report.EarliestCertificateExpiration.IsZero() ||
			certificate.NotAfter.Before(report.EarliestCertificateExpiration) {
			report.EarliestCertificateExpiration = certificate.NotAfter.UTC()
		}
	}
	for _, crl := range crls {
		report.CRLIssuers = append(report.CRLIssuers, crl.Issuer.String())
		if report.EarliestCRLExpiration.IsZero() ||
			crl.NextUpdate.Before(report.EarliestCRLExpiration) {
			report.EarliestCRLExpiration = crl.NextUpdate.UTC()
		}
	}
	sort.Strings(report.CRLIssuers)
	return report, nil
}

type certificateRole uint8

const (
	signingCertificateRole certificateRole = iota + 1
	encryptionCertificateRole
)

func loadEndpointChain(path string, roots []*smx509.Certificate, serverName string, now time.Time, role certificateRole) ([]*smx509.Certificate, error) {
	certificates, err := loadCertificatePEM(path)
	if err != nil {
		return nil, err
	}
	leaf := certificates[0]
	if leaf.BasicConstraintsValid && leaf.IsCA {
		return nil, errors.New("leaf certificate must not be a CA")
	}
	if err := validateCurrentCertificate(leaf, now); err != nil {
		return nil, err
	}
	if err := validateSM2Certificate(leaf); err != nil {
		return nil, err
	}
	if err := validateEndpointRole(leaf, role); err != nil {
		return nil, err
	}
	if err := leaf.VerifyHostname(serverName); err != nil {
		return nil, fmt.Errorf("certificate does not cover server_name: %w", err)
	}
	for index := 1; index < len(certificates); index++ {
		certificate := certificates[index]
		if err := validateCA(certificate, now, false); err != nil {
			return nil, fmt.Errorf("intermediate certificate %d: %w", index, err)
		}
		if err := validateIssuerLink(certificates[index-1], certificate); err != nil {
			return nil, fmt.Errorf("certificate %d does not issue certificate %d: %w", index, index-1, err)
		}
	}
	top := certificates[len(certificates)-1]
	matchedRoot := false
	for _, root := range roots {
		if validateIssuerLink(top, root) != nil {
			continue
		}
		if matchedRoot {
			return nil, errors.New("endpoint certificate chain has multiple matching trust anchors")
		}
		matchedRoot = true
	}
	if !matchedRoot {
		return nil, errors.New("endpoint certificate chain is not directly linked to a configured trust anchor")
	}
	rootPool := smx509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}
	intermediates := smx509.NewCertPool()
	for _, certificate := range certificates[1:] {
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(smx509.VerifyOptions{
		DNSName:       serverName,
		Roots:         rootPool,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []smx509.ExtKeyUsage{smx509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return nil, fmt.Errorf("verify SM2 certificate chain: %w", err)
	}
	if len(chains) == 0 {
		return nil, errors.New("SM2 certificate chain verification returned no chain")
	}
	return certificates, nil
}

func loadCABundle(path string, now time.Time) ([]*smx509.Certificate, error) {
	certificates, err := loadCertificatePEM(path)
	if err != nil {
		return nil, err
	}
	for index, certificate := range certificates {
		if err := validateCA(certificate, now, true); err != nil {
			return nil, fmt.Errorf("CA certificate %d: %w", index, err)
		}
	}
	return certificates, nil
}

func loadCertificatePEM(path string) ([]*smx509.Certificate, error) {
	data, err := readBoundedRegularFile(path, MaxCertificateBytes)
	if err != nil {
		return nil, err
	}
	remaining := data
	certificates := make([]*smx509.Certificate, 0, 2)
	seen := make(map[[sha256.Size]byte]struct{})
	for {
		remaining = bytes.TrimSpace(remaining)
		if len(remaining) == 0 {
			break
		}
		if len(certificates) >= MaxCertificateCount {
			return nil, fmt.Errorf("certificate count exceeds %d", MaxCertificateCount)
		}
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("certificate PEM contains malformed or trailing data")
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("certificate PEM contains an unsupported block")
		}
		certificate, err := smx509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SM2 certificate %d: %w", len(certificates), err)
		}
		if !bytes.Equal(certificate.Raw, block.Bytes) {
			return nil, fmt.Errorf("parse SM2 certificate %d: DER contains trailing data", len(certificates))
		}
		fingerprint := sha256.Sum256(certificate.Raw)
		if _, duplicate := seen[fingerprint]; duplicate {
			return nil, errors.New("certificate PEM contains a duplicate certificate")
		}
		seen[fingerprint] = struct{}{}
		certificates = append(certificates, certificate)
		remaining = rest
	}
	if len(certificates) == 0 {
		return nil, errors.New("certificate PEM contains no certificates")
	}
	return certificates, nil
}

func validateSM2Certificate(certificate *smx509.Certificate) error {
	if certificate.SignatureAlgorithm != smx509.SM2WithSM3 {
		return errors.New("certificate signature algorithm must be SM2-with-SM3")
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || !sameCurve(publicKey.Curve, sm2.P256()) {
		return errors.New("certificate public key must use sm2p256v1")
	}
	return nil
}

func sameCurve(left, right elliptic.Curve) bool {
	if left == nil || right == nil {
		return false
	}
	leftParams, rightParams := left.Params(), right.Params()
	return leftParams != nil && rightParams != nil &&
		leftParams.P.Cmp(rightParams.P) == 0 &&
		leftParams.N.Cmp(rightParams.N) == 0 &&
		leftParams.B.Cmp(rightParams.B) == 0 &&
		leftParams.Gx.Cmp(rightParams.Gx) == 0 &&
		leftParams.Gy.Cmp(rightParams.Gy) == 0 &&
		leftParams.BitSize == rightParams.BitSize
}

func validateCA(certificate *smx509.Certificate, now time.Time, requireSelfSigned bool) error {
	if err := validateCurrentCertificate(certificate, now); err != nil {
		return err
	}
	if err := validateSM2Certificate(certificate); err != nil {
		return err
	}
	if !certificate.BasicConstraintsValid || !certificate.IsCA ||
		certificate.KeyUsage&smx509.KeyUsageCertSign == 0 ||
		certificate.KeyUsage&smx509.KeyUsageCRLSign == 0 {
		return errors.New("certificate is not an SM2 CA authorized for certificate and CRL signing")
	}
	if len(certificate.SubjectKeyId) == 0 || len(certificate.SubjectKeyId) > MaxStringBytes {
		return errors.New("SM2 CA must contain a bounded subject key identifier")
	}
	if requireSelfSigned {
		if !bytes.Equal(certificate.RawIssuer, certificate.RawSubject) ||
			certificate.CheckSignatureFrom(certificate) != nil {
			return errors.New("CA trust anchor must be self-signed")
		}
	}
	return nil
}

func validateIssuerLink(child, issuer *smx509.Certificate) error {
	if !bytes.Equal(child.RawIssuer, issuer.RawSubject) {
		return errors.New("issuer and subject names do not match")
	}
	if len(child.AuthorityKeyId) == 0 ||
		!bytes.Equal(child.AuthorityKeyId, issuer.SubjectKeyId) {
		return errors.New("authority key identifier does not match issuer subject key identifier")
	}
	if err := child.CheckSignatureFrom(issuer); err != nil {
		return err
	}
	return nil
}

func validateCurrentCertificate(certificate *smx509.Certificate, now time.Time) error {
	if now.Before(certificate.NotBefore) {
		return fmt.Errorf("certificate is not valid before %s", certificate.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(certificate.NotAfter) {
		return fmt.Errorf("certificate expired at %s", certificate.NotAfter.UTC().Format(time.RFC3339))
	}
	return nil
}

func validateEndpointRole(certificate *smx509.Certificate, role certificateRole) error {
	if len(certificate.UnknownExtKeyUsage) != 0 ||
		len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != smx509.ExtKeyUsageServerAuth {
		return errors.New("TLCP endpoint certificate EKU must be exactly serverAuth")
	}
	if len(certificateIdentities(certificate)) == 0 {
		return errors.New("TLCP endpoint certificate must contain at least one SAN identity")
	}
	switch role {
	case signingCertificateRole:
		forbidden := smx509.KeyUsageKeyEncipherment |
			smx509.KeyUsageDataEncipherment |
			smx509.KeyUsageKeyAgreement |
			smx509.KeyUsageCertSign |
			smx509.KeyUsageCRLSign |
			smx509.KeyUsageEncipherOnly |
			smx509.KeyUsageDecipherOnly
		if certificate.KeyUsage&smx509.KeyUsageDigitalSignature == 0 ||
			certificate.KeyUsage&forbidden != 0 {
			return errors.New("TLCP signing certificate must allow only a signing role")
		}
	case encryptionCertificateRole:
		allowedRole := smx509.KeyUsageKeyEncipherment |
			smx509.KeyUsageDataEncipherment |
			smx509.KeyUsageKeyAgreement |
			smx509.KeyUsageEncipherOnly |
			smx509.KeyUsageDecipherOnly
		forbidden := smx509.KeyUsageDigitalSignature |
			smx509.KeyUsageContentCommitment |
			smx509.KeyUsageCertSign |
			smx509.KeyUsageCRLSign
		if certificate.KeyUsage&allowedRole == 0 ||
			certificate.KeyUsage&forbidden != 0 {
			return errors.New("TLCP encryption certificate must allow only an encryption/agreement role")
		}
		if certificate.KeyUsage&(smx509.KeyUsageEncipherOnly|smx509.KeyUsageDecipherOnly) != 0 &&
			certificate.KeyUsage&smx509.KeyUsageKeyAgreement == 0 {
			return errors.New("TLCP encryption certificate encipherOnly/decipherOnly requires keyAgreement")
		}
	default:
		return errors.New("unknown TLCP certificate role")
	}
	return nil
}

func validateDualCertificateIdentity(signing, encryption *smx509.Certificate) error {
	if bytes.Equal(signing.Raw, encryption.Raw) {
		return errors.New("TLCP signing and encryption certificates must be distinct")
	}
	signingKey, signingOK := signing.PublicKey.(*ecdsa.PublicKey)
	encryptionKey, encryptionOK := encryption.PublicKey.(*ecdsa.PublicKey)
	if !signingOK || !encryptionOK ||
		(signingKey.X.Cmp(encryptionKey.X) == 0 && signingKey.Y.Cmp(encryptionKey.Y) == 0) {
		return errors.New("TLCP signing and encryption certificates must use distinct SM2 public keys")
	}
	if !bytes.Equal(signing.RawSubject, encryption.RawSubject) {
		return errors.New("TLCP signing and encryption certificate subjects must be byte-identical")
	}
	if !equalStrings(certificateIdentities(signing), certificateIdentities(encryption)) {
		return errors.New("TLCP signing and encryption certificate SAN identities must be identical")
	}
	return nil
}

func certificateIdentities(certificate *smx509.Certificate) []string {
	var result []string
	for _, value := range certificate.DNSNames {
		result = append(result, "dns:"+strings.ToLower(value))
	}
	for _, value := range certificate.EmailAddresses {
		result = append(result, "email:"+strings.ToLower(value))
	}
	for _, value := range certificate.IPAddresses {
		result = append(result, "ip:"+value.String())
	}
	for _, value := range certificate.URIs {
		result = append(result, "uri:"+value.String())
	}
	sort.Strings(result)
	return result
}

func loadAndValidateCRLs(config Revocation, set certificateSet, now time.Time) ([]*smx509.RevocationList, error) {
	maxStaleness, _ := time.ParseDuration(config.MaxStaleness)
	cas := append(
		append([]*smx509.Certificate(nil), set.serverRoots...),
		set.clientRoots...,
	)
	for _, certificate := range set.serverCertificates {
		if certificate.IsCA {
			cas = append(cas, certificate)
		}
	}
	cas = uniqueCertificates(cas)
	crls := make([]*smx509.RevocationList, 0, len(config.CRLFiles))
	seenIssuer := make(map[[sha256.Size]byte]struct{}, len(config.CRLFiles))
	for index, path := range config.CRLFiles {
		crl, err := loadCRL(path)
		if err != nil {
			return nil, fmt.Errorf("load CRL %d: %w", index, err)
		}
		if crl.SignatureAlgorithm != smx509.SM2WithSM3 {
			return nil, fmt.Errorf("CRL %d signature algorithm must be SM2-with-SM3", index)
		}
		issuer, err := findCRLIssuer(crl, cas)
		if err != nil {
			return nil, fmt.Errorf("CRL %d: %w", index, err)
		}
		issuerFingerprint := sha256.Sum256(issuer.Raw)
		if _, duplicate := seenIssuer[issuerFingerprint]; duplicate {
			return nil, fmt.Errorf("CRL %d duplicates the issuer of an earlier CRL", index)
		}
		seenIssuer[issuerFingerprint] = struct{}{}
		if now.Before(crl.ThisUpdate) {
			return nil, fmt.Errorf("CRL %d is not valid before %s", index, crl.ThisUpdate.UTC().Format(time.RFC3339))
		}
		if crl.NextUpdate.IsZero() || !now.Before(crl.NextUpdate) {
			return nil, fmt.Errorf("CRL %d is expired", index)
		}
		if now.Sub(crl.ThisUpdate) > maxStaleness {
			return nil, fmt.Errorf("CRL %d exceeds max_staleness", index)
		}
		if err := validateRevokedEntries(crl); err != nil {
			return nil, fmt.Errorf("CRL %d: %w", index, err)
		}
		for _, certificate := range set.serverCertificates {
			if validateIssuerLink(certificate, issuer) == nil &&
				crlRevokes(crl, certificate.SerialNumber) {
				return nil, fmt.Errorf("CRL %d revokes a configured TLCP server certificate", index)
			}
		}
		crls = append(crls, crl)
	}
	if len(seenIssuer) != len(cas) {
		return nil, errors.New("every TLCP server issuer and client trust anchor requires exactly one current CRL")
	}
	return crls, nil
}

func loadCRL(path string) (*smx509.RevocationList, error) {
	data, err := readBoundedRegularFile(path, MaxCRLBytes)
	if err != nil {
		return nil, err
	}
	remaining := bytes.TrimSpace(data)
	block, rest := pem.Decode(remaining)
	if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("CRL must contain exactly one strict X509 CRL PEM block")
	}
	crl, err := smx509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse SM2 CRL: %w", err)
	}
	if !bytes.Equal(crl.Raw, block.Bytes) {
		return nil, errors.New("parse SM2 CRL: DER contains trailing data")
	}
	return crl, nil
}

func findCRLIssuer(crl *smx509.RevocationList, cas []*smx509.Certificate) (*smx509.Certificate, error) {
	if len(crl.AuthorityKeyId) == 0 {
		return nil, errors.New("CRL authority key identifier is required")
	}
	var matched *smx509.Certificate
	for _, ca := range cas {
		if !bytes.Equal(crl.RawIssuer, ca.RawSubject) {
			continue
		}
		if !bytes.Equal(crl.AuthorityKeyId, ca.SubjectKeyId) {
			continue
		}
		if err := crl.CheckSignatureFrom(ca); err != nil {
			continue
		}
		if matched != nil {
			return nil, errors.New("CRL issuer is ambiguous")
		}
		matched = ca
	}
	if matched == nil {
		return nil, errors.New("CRL is not issued by a configured SM2 CA")
	}
	return matched, nil
}

func validateRevokedEntries(crl *smx509.RevocationList) error {
	seen := make(map[string]struct{}, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 {
			return errors.New("CRL contains an invalid certificate serial")
		}
		serial := entry.SerialNumber.Text(16)
		if _, duplicate := seen[serial]; duplicate {
			return errors.New("CRL contains a duplicate certificate serial")
		}
		seen[serial] = struct{}{}
	}
	return nil
}

func crlRevokes(crl *smx509.RevocationList, serial *big.Int) bool {
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}

func uniqueCertificates(certificates []*smx509.Certificate) []*smx509.Certificate {
	result := make([]*smx509.Certificate, 0, len(certificates))
	seen := make(map[[sha256.Size]byte]struct{}, len(certificates))
	for _, certificate := range certificates {
		fingerprint := sha256.Sum256(certificate.Raw)
		if _, duplicate := seen[fingerprint]; duplicate {
			continue
		}
		seen[fingerprint] = struct{}{}
		result = append(result, certificate)
	}
	return result
}

func certificateFingerprint(certificate *smx509.Certificate) string {
	value := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(value[:])
}

func publicKeyFingerprint(certificate *smx509.Certificate) string {
	der, err := smx509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return ""
	}
	value := sha256.Sum256(der)
	return hex.EncodeToString(value[:])
}

func certificateFingerprints(certificates []*smx509.Certificate) []string {
	result := make([]string, 0, len(certificates))
	for _, certificate := range certificates {
		result = append(result, certificateFingerprint(certificate))
	}
	sort.Strings(result)
	return result
}
