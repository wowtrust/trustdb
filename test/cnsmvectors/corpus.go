// Package cnsmvectors exposes the immutable CN_SM_V1 interoperability corpus
// used by TrustDB component tests. It is test material, not a production key
// or configuration API.
package cnsmvectors

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/keydescriptor"
	"github.com/wowtrust/trustdb/v2/internal/model"
	"github.com/wowtrust/trustdb/v2/internal/trustcrypto"
)

const (
	Schema       = "trustdb.cn-sm-v1.interoperability-v1"
	CorpusName   = "cn-sm-v1-interoperability-v1.json"
	ChecksumName = "cn-sm-v1-interoperability-v1.sha256"
)

//go:embed cn-sm-v1-interoperability-v1.json
var embeddedCorpus []byte

//go:embed cn-sm-v1-interoperability-v1.sha256
var embeddedChecksum []byte

type Corpus struct {
	Schema        string         `json:"schema"`
	CryptoSuite   string         `json:"crypto_suite"`
	Provenance    Provenance     `json:"provenance"`
	Contents      []Content      `json:"contents"`
	Identities    Identities     `json:"identities"`
	RecordID      string         `json:"record_id"`
	Artifacts     Artifacts      `json:"artifacts"`
	NegativeCases []NegativeCase `json:"negative_cases"`
}

type Provenance struct {
	GeneratorVersion         uint64   `json:"generator_version"`
	GeneratorCommand         string   `json:"generator_command"`
	CanonicalEncoding        string   `json:"canonical_encoding"`
	SignatureNonceDerivation string   `json:"signature_nonce_derivation"`
	SM2UserIDASCII           string   `json:"sm2_user_id_ascii"`
	NetworkRequired          bool     `json:"network_required"`
	Sources                  []string `json:"sources"`
	IndependentOracles       []string `json:"independent_oracles"`
}

type Content struct {
	ID        string `json:"id"`
	BytesHex  string `json:"bytes_hex"`
	DigestHex string `json:"sm3_hex"`
}

type Identities struct {
	Client   Identity `json:"client"`
	Server   Identity `json:"server"`
	Registry Identity `json:"registry"`
}

type Identity struct {
	KeyID             string `json:"key_id"`
	PrivateKeyHex     string `json:"private_key_hex"`
	PublicKeyHex      string `json:"public_key_hex"`
	DescriptorCBORHex string `json:"descriptor_cbor_hex"`
}

type Artifacts struct {
	ClientClaim        Artifact `json:"client_claim"`
	SignedClaim        Artifact `json:"signed_claim"`
	ServerRecord       Artifact `json:"server_record"`
	AcceptedReceipt    Artifact `json:"accepted_receipt"`
	CommittedReceipt   Artifact `json:"committed_receipt"`
	BatchRoot          Artifact `json:"batch_root"`
	SecondaryBatchRoot Artifact `json:"secondary_batch_root"`
	ProofBundle        Artifact `json:"proof_bundle"`
	GlobalLogLeaf      Artifact `json:"global_log_leaf"`
	SignedTreeHead     Artifact `json:"signed_tree_head"`
	GlobalLogProof     Artifact `json:"global_log_proof"`
	SingleProof        Artifact `json:"single_proof"`
	KeyEvent           Artifact `json:"key_event"`
	KeyRegistryV2      Artifact `json:"key_registry_v2"`
}

type Artifact struct {
	Encoding          string `json:"encoding"`
	BytesHex          string `json:"bytes_hex"`
	SignatureInputHex string `json:"signature_input_hex,omitempty"`
	SignatureDERHex   string `json:"signature_der_hex,omitempty"`
}

type NegativeCase struct {
	ID       string `json:"id"`
	Mutation string `json:"mutation"`
	Expected string `json:"expected"`
}

type Decoded struct {
	ClientClaim        model.ClientClaim
	SignedClaim        model.SignedClaim
	ServerRecord       model.ServerRecord
	AcceptedReceipt    model.AcceptedReceipt
	CommittedReceipt   model.CommittedReceipt
	BatchRoot          model.BatchRoot
	SecondaryBatchRoot model.BatchRoot
	ProofBundle        model.ProofBundle
	GlobalLogLeaf      model.GlobalLogLeaf
	SignedTreeHead     model.SignedTreeHead
	GlobalLogProof     model.GlobalLogProof
	SingleProof        model.SingleProof
	KeyEvent           model.KeyEvent
	KeyRegistryV2      []byte
}

func EmbeddedBytes() []byte {
	return append([]byte(nil), embeddedCorpus...)
}

func EmbeddedChecksum() string {
	return strings.TrimSpace(string(embeddedChecksum))
}

func Load() (Corpus, error) {
	if err := verifyChecksum(embeddedCorpus, embeddedChecksum); err != nil {
		return Corpus{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(embeddedCorpus))
	decoder.DisallowUnknownFields()
	var corpus Corpus
	if err := decoder.Decode(&corpus); err != nil {
		return Corpus{}, fmt.Errorf("cnsmvectors: decode corpus: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Corpus{}, fmt.Errorf("cnsmvectors: trailing corpus data: %w", err)
	}
	if corpus.Schema != Schema {
		return Corpus{}, fmt.Errorf("cnsmvectors: schema %q, want %q", corpus.Schema, Schema)
	}
	if corpus.CryptoSuite != "CN_SM_V1" {
		return Corpus{}, fmt.Errorf("cnsmvectors: crypto_suite %q, want CN_SM_V1", corpus.CryptoSuite)
	}
	return corpus, nil
}

func (c Corpus) Decode() (Decoded, error) {
	var out Decoded
	for _, item := range []struct {
		name     string
		artifact Artifact
		target   any
	}{
		{"client_claim", c.Artifacts.ClientClaim, &out.ClientClaim},
		{"signed_claim", c.Artifacts.SignedClaim, &out.SignedClaim},
		{"server_record", c.Artifacts.ServerRecord, &out.ServerRecord},
		{"accepted_receipt", c.Artifacts.AcceptedReceipt, &out.AcceptedReceipt},
		{"committed_receipt", c.Artifacts.CommittedReceipt, &out.CommittedReceipt},
		{"batch_root", c.Artifacts.BatchRoot, &out.BatchRoot},
		{"secondary_batch_root", c.Artifacts.SecondaryBatchRoot, &out.SecondaryBatchRoot},
		{"proof_bundle", c.Artifacts.ProofBundle, &out.ProofBundle},
		{"global_log_leaf", c.Artifacts.GlobalLogLeaf, &out.GlobalLogLeaf},
		{"signed_tree_head", c.Artifacts.SignedTreeHead, &out.SignedTreeHead},
		{"global_log_proof", c.Artifacts.GlobalLogProof, &out.GlobalLogProof},
		{"single_proof", c.Artifacts.SingleProof, &out.SingleProof},
		{"key_event", c.Artifacts.KeyEvent, &out.KeyEvent},
	} {
		raw, err := item.artifact.Bytes()
		if err != nil {
			return Decoded{}, fmt.Errorf("cnsmvectors: %s: %w", item.name, err)
		}
		if item.artifact.Encoding != "cbor-core-deterministic-rfc8949" {
			return Decoded{}, fmt.Errorf("cnsmvectors: %s encoding %q is not canonical CBOR", item.name, item.artifact.Encoding)
		}
		if err := cborx.Unmarshal(raw, item.target); err != nil {
			return Decoded{}, fmt.Errorf("cnsmvectors: decode %s: %w", item.name, err)
		}
		canonical, err := cborx.Marshal(item.target)
		if err != nil {
			return Decoded{}, fmt.Errorf("cnsmvectors: re-encode %s: %w", item.name, err)
		}
		if !bytes.Equal(canonical, raw) {
			return Decoded{}, fmt.Errorf("cnsmvectors: %s is not canonical CBOR", item.name)
		}
	}
	if c.Artifacts.KeyRegistryV2.Encoding != "trustdb.key-registry.v2" {
		return Decoded{}, fmt.Errorf("cnsmvectors: key registry encoding %q", c.Artifacts.KeyRegistryV2.Encoding)
	}
	registry, err := c.Artifacts.KeyRegistryV2.Bytes()
	if err != nil {
		return Decoded{}, fmt.Errorf("cnsmvectors: key registry: %w", err)
	}
	out.KeyRegistryV2 = registry
	return out, nil
}

func (a Artifact) Bytes() ([]byte, error) {
	raw, err := hex.DecodeString(a.BytesHex)
	if err != nil {
		return nil, fmt.Errorf("invalid artifact hex: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("artifact is empty")
	}
	return raw, nil
}

func (a Artifact) SignatureInput() ([]byte, error) {
	if a.SignatureInputHex == "" {
		return nil, errors.New("artifact has no signature input")
	}
	raw, err := hex.DecodeString(a.SignatureInputHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature input hex: %w", err)
	}
	return raw, nil
}

func (a Artifact) SignatureDER() ([]byte, error) {
	if a.SignatureDERHex == "" {
		return nil, errors.New("artifact has no signature")
	}
	raw, err := hex.DecodeString(a.SignatureDERHex)
	if err != nil {
		return nil, fmt.Errorf("invalid signature DER hex: %w", err)
	}
	return raw, nil
}

func (i Identity) Descriptor() (keydescriptor.Descriptor, error) {
	raw, err := hex.DecodeString(i.DescriptorCBORHex)
	if err != nil {
		return keydescriptor.Descriptor{}, fmt.Errorf("cnsmvectors: descriptor hex: %w", err)
	}
	return keydescriptor.Unmarshal(raw)
}

func (i Identity) PublicKeyDescriptor() (trustcrypto.PublicKeyDescriptor, error) {
	descriptor, err := i.Descriptor()
	if err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return descriptor.PublicKeyDescriptor()
}

func (c Content) Bytes() ([]byte, error) {
	raw, err := hex.DecodeString(c.BytesHex)
	if err != nil {
		return nil, fmt.Errorf("cnsmvectors: content %q: %w", c.ID, err)
	}
	return raw, nil
}

func verifyChecksum(data, checksum []byte) error {
	fields := strings.Fields(string(checksum))
	if len(fields) != 2 || fields[1] != CorpusName {
		return errors.New("cnsmvectors: malformed corpus checksum")
	}
	want, err := hex.DecodeString(fields[0])
	if err != nil || len(want) != sha256.Size {
		return errors.New("cnsmvectors: malformed SHA-256 checksum")
	}
	got := sha256.Sum256(data)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("cnsmvectors: corpus checksum mismatch: got %x want %x", got, want)
	}
	return nil
}
