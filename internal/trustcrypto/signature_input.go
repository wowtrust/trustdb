package trustcrypto

import (
	"fmt"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
)

type SignaturePurpose string

const (
	SignaturePurposeClientClaim      SignaturePurpose = "client_claim"
	SignaturePurposeAcceptedReceipt  SignaturePurpose = "accepted_receipt"
	SignaturePurposeCommittedReceipt SignaturePurpose = "committed_receipt"
	SignaturePurposeKeyEvent         SignaturePurpose = "key_event"
	SignaturePurposeSignedTreeHead   SignaturePurpose = "signed_tree_head"
)

func SignatureInputForSuite(suiteID cryptosuite.ID, purpose SignaturePurpose, payload []byte) ([]byte, error) {
	return AppendSignatureInputForSuite(nil, suiteID, purpose, payload)
}

func AppendSignatureInputForSuite(dst []byte, suiteID cryptosuite.ID, purpose SignaturePurpose, payload []byte) ([]byte, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return nil, err
	}
	domain, err := signatureDomain(suite, purpose)
	if err != nil {
		return nil, err
	}
	switch suite.Encoding.SignatureInputEncoding {
	case cryptosuite.SignatureInputLegacyV1:
		dst = append(dst, domain...)
		dst = append(dst, suite.Encoding.DomainSeparator)
	case cryptosuite.SignatureInputSuiteFramedV2:
		dst = append(dst, domain...)
		dst = append(dst, suite.Encoding.DomainSeparator)
		dst = append(dst, suite.ID...)
		dst = append(dst, suite.Encoding.DomainSeparator)
	default:
		return nil, fmt.Errorf("%w: signature input %q for suite %s", ErrUnsupportedEncoding, suite.Encoding.SignatureInputEncoding, suite.ID)
	}
	dst = append(dst, payload...)
	return dst, nil
}

func signatureDomain(suite cryptosuite.Suite, purpose SignaturePurpose) (string, error) {
	var domain string
	switch purpose {
	case SignaturePurposeClientClaim:
		domain = suite.Domains.ClientClaimSigning
	case SignaturePurposeAcceptedReceipt:
		domain = suite.Domains.AcceptedReceipt
	case SignaturePurposeCommittedReceipt:
		domain = suite.Domains.CommittedReceipt
	case SignaturePurposeKeyEvent:
		domain = suite.Domains.KeyEventSigning
	case SignaturePurposeSignedTreeHead:
		domain = suite.Domains.SignedTreeHead
	default:
		return "", fmt.Errorf("%w: signature purpose %q", ErrUnsupportedEncoding, purpose)
	}
	if domain == "" {
		return "", fmt.Errorf("%w: empty signature domain for %q in suite %s", ErrUnsupportedEncoding, purpose, suite.ID)
	}
	return domain, nil
}
