// Package standardsdk isolates the pinned FISCO BCOS Go SDK from TrustDB's
// scheduler, proof model, configuration, and portable build graph.
package standardsdk

import (
	"context"
	"errors"
	"time"

	"github.com/wowtrust/trustdb/v2/internal/anchor/fiscobcos"
)

var ErrSDKNotBuilt = errors.New("FISCO BCOS SDK support is not present in this build")

// AccountSigner exposes only a non-exportable mode-bound signing capability.
// Standard mode returns the native 65-byte secp256k1 signature. Guomi mode
// returns a canonical DER SM2 signature; the native driver verifies it and
// appends the configured public key for BCOS transaction serialization.
// Private key bytes are never requested.
type AccountSigner interface {
	PublicKey(context.Context) ([]byte, error)
	SignDigest(context.Context, []byte) ([]byte, error)
}

type Config struct {
	TrustConfig   fiscobcos.TrustConfig
	AccountSigner AccountSigner
	Clock         func() time.Time
}

type Factory interface {
	NewDrivers(context.Context, Config) ([]fiscobcos.Driver, error)
}

type NativeFactory struct{}
