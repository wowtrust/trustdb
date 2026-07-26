package merkle

import (
	"crypto/sha256"
	"fmt"

	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

// DigestSize is fixed by both TrustDB v1 suites. Equal digest lengths never
// imply compatibility: every operation also requires an exact suite and tree
// algorithm match through Profile.
const DigestSize = 32

type digest = [DigestSize]byte

// Profile is an immutable RFC6962 hashing profile. Its fields are private so
// callers cannot create unregistered combinations of suites, algorithms,
// prefixes, and hash factories.
type Profile struct {
	suite       cryptosuite.ID
	algorithm   string
	hashAlg     string
	hashKind    uint8
	leafPrefix  byte
	nodePrefix  byte
	digestBytes int
}

const (
	hashKindSHA256 uint8 = iota + 1
	hashKindSM3
)

var defaultProfile = mustProfile(cryptosuite.INTLV1)

func mustProfile(suiteID cryptosuite.ID) Profile {
	profile, err := ProfileForSuite(suiteID)
	if err != nil {
		panic(err)
	}
	return profile
}

func ProfileForSuite(suiteID cryptosuite.ID) (Profile, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return Profile{}, err
	}
	return ProfileForAlgorithm(suiteID, suite.Merkle.Algorithm)
}

func ProfileForAlgorithm(suiteID cryptosuite.ID, treeAlgorithm string) (Profile, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return Profile{}, err
	}
	if treeAlgorithm != suite.Merkle.Algorithm {
		return Profile{}, fmt.Errorf("merkle: tree algorithm %q does not match suite %s profile %q", treeAlgorithm, suiteID, suite.Merkle.Algorithm)
	}
	factory, err := trustcrypto.HashFactoryForSuite(suiteID, suite.Merkle.Hash.Algorithm)
	if err != nil {
		return Profile{}, err
	}
	if suite.Merkle.Hash.DigestBytes != DigestSize || factory.Size() != DigestSize {
		return Profile{}, fmt.Errorf("merkle: suite %s digest size %d is unsupported", suiteID, suite.Merkle.Hash.DigestBytes)
	}
	if suite.Merkle.LeafPrefix == suite.Merkle.NodePrefix {
		return Profile{}, fmt.Errorf("merkle: suite %s has ambiguous domain prefixes", suiteID)
	}
	var hashKind uint8
	switch factory.Algorithm() {
	case cryptosuite.HashSHA256:
		hashKind = hashKindSHA256
	case cryptosuite.HashSM3:
		hashKind = hashKindSM3
	default:
		return Profile{}, fmt.Errorf("merkle: suite %s uses unsupported hash %q", suiteID, factory.Algorithm())
	}
	return Profile{
		suite:       suiteID,
		algorithm:   treeAlgorithm,
		hashAlg:     factory.Algorithm(),
		hashKind:    hashKind,
		leafPrefix:  suite.Merkle.LeafPrefix,
		nodePrefix:  suite.Merkle.NodePrefix,
		digestBytes: suite.Merkle.Hash.DigestBytes,
	}, nil
}

func (p Profile) Suite() cryptosuite.ID { return p.suite }
func (p Profile) Algorithm() string     { return p.algorithm }
func (p Profile) HashAlgorithm() string { return p.hashAlg }
func (p Profile) Size() int             { return p.digestBytes }

func (p Profile) valid() bool {
	return p.suite != "" && p.algorithm != "" && p.hashAlg != "" && p.hashKind != 0 && p.digestBytes == DigestSize && p.leafPrefix != p.nodePrefix
}

func (p Profile) hashBytes(data []byte) digest {
	switch p.hashKind {
	case hashKindSHA256:
		return sha256.Sum256(data)
	case hashKindSM3:
		return sm3.Sum(data)
	default:
		panic("merkle: invalid hash profile")
	}
}

func EmptyRootForSuite(suiteID cryptosuite.ID, treeAlgorithm string) ([]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	return cloneHash(profile.hashBytes(nil)), nil
}

func HashLeafPayloadForSuite(suiteID cryptosuite.ID, treeAlgorithm string, payload []byte) ([]byte, error) {
	profile, err := ProfileForAlgorithm(suiteID, treeAlgorithm)
	if err != nil {
		return nil, err
	}
	input := make([]byte, 1+len(payload))
	input[0] = profile.leafPrefix
	copy(input[1:], payload)
	return cloneHash(profile.hashBytes(input)), nil
}
