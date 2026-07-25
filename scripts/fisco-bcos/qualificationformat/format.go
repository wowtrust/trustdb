// Package qualificationformat defines the verifier-local trust-root file used
// by the FISCO BCOS four-node qualification gate. The .sproof remains a
// standalone evidence file; this sidecar deliberately contains local trust
// roots that are never adopted from the evidence itself.
package qualificationformat

import (
	"github.com/wowtrust/trustdb/internal/anchor/fiscobcos"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const TrustRootsSchema = "trustdb.fisco-bcos-qualification-trust-roots.v1"

type TrustRoots struct {
	Schema           string                            `json:"schema"`
	CryptoSuite      cryptosuite.ID                    `json:"crypto_suite"`
	ClientPublicKeys []trustcrypto.PublicKeyDescriptor `json:"client_public_keys"`
	ServerPublicKeys []trustcrypto.PublicKeyDescriptor `json:"server_public_keys"`
	FISCOBCOS        fiscobcos.TrustConfig             `json:"fisco_bcos"`
	ExpectedRecordID string                            `json:"expected_record_id"`
}
