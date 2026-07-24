package fiscobcos

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

var payloadMagic = [8]byte{'T', 'D', 'B', 'B', 'C', 'O', 'S', 0}

const (
	MaxPayloadBytes = 64 << 10
	maxPayloadField = 16 << 10
	identifierBytes = 32
)

// AnchorPayload is chain-neutral by design. The exact same canonical bytes can
// be submitted to a standard or Guomi BCOS network. Network, contract, crypto
// mode, and checkpoint binding belongs to AnchorProof.ChainContextID.
type AnchorPayload struct {
	Version            uint16
	CryptoSuite        cryptosuite.ID
	TreeAlgorithm      string
	RootHashAlgorithm  string
	STHDigestAlgorithm string
	NodeID             string
	LogID              string
	SinkName           string
	TreeSize           uint64
	RootHash           []byte
	SignedSTHDigest    []byte
	StreamID           []byte
	AnchorID           []byte
}

func NewAnchorPayload(suiteID cryptosuite.ID, sth model.SignedTreeHead) (AnchorPayload, error) {
	suite, err := validateSignedTreeHead(suiteID, sth)
	if err != nil {
		return AnchorPayload{}, err
	}
	sthBytes, err := cborx.Marshal(sth)
	if err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: encode signed STH: %v", ErrInvalidPayload, err)
	}
	sthDigest, err := trustcrypto.HashBytesForSuite(suiteID, suite.AnchorDigest.Algorithm, sthBytes)
	if err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: digest signed STH: %v", ErrInvalidPayload, err)
	}
	payload := AnchorPayload{
		Version:            PayloadVersion,
		CryptoSuite:        suiteID,
		TreeAlgorithm:      sth.TreeAlg,
		RootHashAlgorithm:  suite.Merkle.Hash.Algorithm,
		STHDigestAlgorithm: suite.AnchorDigest.Algorithm,
		NodeID:             sth.NodeID,
		LogID:              sth.LogID,
		SinkName:           SinkName,
		TreeSize:           sth.TreeSize,
		RootHash:           append([]byte(nil), sth.RootHash...),
		SignedSTHDigest:    sthDigest,
	}
	payload.StreamID, err = deriveStreamID(payload)
	if err != nil {
		return AnchorPayload{}, err
	}
	payload.AnchorID, err = deriveAnchorID(payload)
	if err != nil {
		return AnchorPayload{}, err
	}
	return payload, nil
}

func MarshalPayload(payload AnchorPayload) ([]byte, error) {
	if err := validatePayload(payload); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Grow(256 + len(payload.NodeID) + len(payload.LogID))
	buf.Write(payloadMagic[:])
	_ = binary.Write(&buf, binary.BigEndian, payload.Version)
	for _, field := range [][]byte{
		[]byte(payload.CryptoSuite),
		[]byte(payload.TreeAlgorithm),
		[]byte(payload.RootHashAlgorithm),
		[]byte(payload.STHDigestAlgorithm),
		[]byte(payload.NodeID),
		[]byte(payload.LogID),
		[]byte(payload.SinkName),
	} {
		if err := writeLP16(&buf, field); err != nil {
			return nil, err
		}
	}
	_ = binary.Write(&buf, binary.BigEndian, payload.TreeSize)
	if err := writeLP16(&buf, payload.RootHash); err != nil {
		return nil, err
	}
	if err := writeLP16(&buf, payload.SignedSTHDigest); err != nil {
		return nil, err
	}
	buf.Write(payload.StreamID)
	buf.Write(payload.AnchorID)
	if buf.Len() > MaxPayloadBytes {
		return nil, fmt.Errorf("%w: encoded payload is %d bytes, limit %d", ErrInvalidPayload, buf.Len(), MaxPayloadBytes)
	}
	return buf.Bytes(), nil
}

func UnmarshalPayload(data []byte) (AnchorPayload, error) {
	if len(data) == 0 || len(data) > MaxPayloadBytes {
		return AnchorPayload{}, fmt.Errorf("%w: encoded payload size %d is outside 1..%d", ErrInvalidPayload, len(data), MaxPayloadBytes)
	}
	r := bytes.NewReader(data)
	var magic [8]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil || magic != payloadMagic {
		return AnchorPayload{}, fmt.Errorf("%w: invalid magic", ErrInvalidPayload)
	}
	var payload AnchorPayload
	if err := binary.Read(r, binary.BigEndian, &payload.Version); err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: read version: %v", ErrInvalidPayload, err)
	}
	fields := make([][]byte, 7)
	for i := range fields {
		field, err := readLP16(r)
		if err != nil {
			return AnchorPayload{}, err
		}
		fields[i] = field
	}
	payload.CryptoSuite = cryptosuite.ID(fields[0])
	payload.TreeAlgorithm = string(fields[1])
	payload.RootHashAlgorithm = string(fields[2])
	payload.STHDigestAlgorithm = string(fields[3])
	payload.NodeID = string(fields[4])
	payload.LogID = string(fields[5])
	payload.SinkName = string(fields[6])
	if err := binary.Read(r, binary.BigEndian, &payload.TreeSize); err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: read tree_size: %v", ErrInvalidPayload, err)
	}
	var err error
	if payload.RootHash, err = readLP16(r); err != nil {
		return AnchorPayload{}, err
	}
	if payload.SignedSTHDigest, err = readLP16(r); err != nil {
		return AnchorPayload{}, err
	}
	payload.StreamID = make([]byte, identifierBytes)
	if _, err := io.ReadFull(r, payload.StreamID); err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: read stream_id: %v", ErrInvalidPayload, err)
	}
	payload.AnchorID = make([]byte, identifierBytes)
	if _, err := io.ReadFull(r, payload.AnchorID); err != nil {
		return AnchorPayload{}, fmt.Errorf("%w: read anchor_id: %v", ErrInvalidPayload, err)
	}
	if r.Len() != 0 {
		return AnchorPayload{}, fmt.Errorf("%w: trailing %d bytes", ErrInvalidPayload, r.Len())
	}
	if err := validatePayload(payload); err != nil {
		return AnchorPayload{}, err
	}
	return payload, nil
}

func ValidatePayloadAgainstSTH(payload AnchorPayload, sth model.SignedTreeHead) error {
	want, err := NewAnchorPayload(payload.CryptoSuite, sth)
	if err != nil {
		return err
	}
	gotBytes, err := MarshalPayload(payload)
	if err != nil {
		return err
	}
	wantBytes, err := MarshalPayload(want)
	if err != nil {
		return err
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		return fmt.Errorf("%w: payload does not exactly bind the supplied signed STH", ErrInvalidPayload)
	}
	return nil
}

func AnchorIDString(payload AnchorPayload) string {
	return hex.EncodeToString(payload.AnchorID)
}

func validateSignedTreeHead(suiteID cryptosuite.ID, sth model.SignedTreeHead) (cryptosuite.Suite, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return cryptosuite.Suite{}, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if sth.SchemaVersion != model.SchemaSignedTreeHead {
		return cryptosuite.Suite{}, fmt.Errorf("%w: signed STH schema_version=%q", ErrInvalidPayload, sth.SchemaVersion)
	}
	if strings.TrimSpace(sth.NodeID) == "" || strings.TrimSpace(sth.LogID) == "" {
		return cryptosuite.Suite{}, fmt.Errorf("%w: signed STH node_id and log_id are required", ErrInvalidPayload)
	}
	if sth.TreeSize == 0 {
		return cryptosuite.Suite{}, fmt.Errorf("%w: signed STH tree_size must be positive", ErrInvalidPayload)
	}
	if sth.TreeAlg != suite.Merkle.Algorithm {
		return cryptosuite.Suite{}, fmt.Errorf("%w: suite %s requires tree_alg=%s, got %q", ErrInvalidPayload, suiteID, suite.Merkle.Algorithm, sth.TreeAlg)
	}
	if len(sth.RootHash) != suite.Merkle.Hash.DigestBytes {
		return cryptosuite.Suite{}, fmt.Errorf("%w: root_hash length=%d, want %d", ErrInvalidPayload, len(sth.RootHash), suite.Merkle.Hash.DigestBytes)
	}
	if sth.Signature.Alg != suite.Signature.Algorithm || strings.TrimSpace(sth.Signature.KeyID) == "" || len(sth.Signature.Signature) == 0 {
		return cryptosuite.Suite{}, fmt.Errorf("%w: signed STH signature does not match suite %s", ErrInvalidPayload, suiteID)
	}
	return suite, nil
}

func validatePayload(payload AnchorPayload) error {
	if payload.Version != PayloadVersion {
		return fmt.Errorf("%w: unsupported version %d", ErrInvalidPayload, payload.Version)
	}
	suite, err := cryptosuite.RequireKnown(payload.CryptoSuite)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	if payload.TreeAlgorithm != suite.Merkle.Algorithm || payload.RootHashAlgorithm != suite.Merkle.Hash.Algorithm || payload.STHDigestAlgorithm != suite.AnchorDigest.Algorithm {
		return fmt.Errorf("%w: suite %s algorithm parameters do not match", ErrInvalidPayload, payload.CryptoSuite)
	}
	if strings.TrimSpace(payload.NodeID) == "" || strings.TrimSpace(payload.LogID) == "" || payload.SinkName != SinkName {
		return fmt.Errorf("%w: node_id, log_id, and sink_name=%q are required", ErrInvalidPayload, SinkName)
	}
	for name, value := range map[string]string{
		"crypto_suite": string(payload.CryptoSuite), "tree_algorithm": payload.TreeAlgorithm,
		"root_hash_algorithm": payload.RootHashAlgorithm, "sth_digest_algorithm": payload.STHDigestAlgorithm,
		"node_id": payload.NodeID, "log_id": payload.LogID, "sink_name": payload.SinkName,
	} {
		if len(value) == 0 || len(value) > maxPayloadField {
			return fmt.Errorf("%w: %s length=%d", ErrInvalidPayload, name, len(value))
		}
	}
	if payload.TreeSize == 0 {
		return fmt.Errorf("%w: tree_size must be positive", ErrInvalidPayload)
	}
	if len(payload.RootHash) != suite.Merkle.Hash.DigestBytes || len(payload.SignedSTHDigest) != suite.AnchorDigest.DigestBytes {
		return fmt.Errorf("%w: digest length does not match suite %s", ErrInvalidPayload, payload.CryptoSuite)
	}
	if len(payload.StreamID) != identifierBytes || len(payload.AnchorID) != identifierBytes {
		return fmt.Errorf("%w: stream_id and anchor_id must be %d bytes", ErrInvalidPayload, identifierBytes)
	}
	wantStream, err := deriveStreamID(payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload.StreamID, wantStream) {
		return fmt.Errorf("%w: stream_id mismatch", ErrInvalidPayload)
	}
	wantAnchor, err := deriveAnchorID(payload)
	if err != nil {
		return err
	}
	if !bytes.Equal(payload.AnchorID, wantAnchor) {
		return fmt.Errorf("%w: anchor_id mismatch", ErrInvalidPayload)
	}
	return nil
}

func deriveStreamID(payload AnchorPayload) ([]byte, error) {
	framed, err := frameDomain(DomainStreamID,
		[]byte(payload.CryptoSuite), []byte(payload.NodeID), []byte(payload.LogID), []byte(payload.SinkName))
	if err != nil {
		return nil, err
	}
	return protocolDigestForSuite(payload.CryptoSuite, framed)
}

func deriveAnchorID(payload AnchorPayload) ([]byte, error) {
	var treeSize [8]byte
	binary.BigEndian.PutUint64(treeSize[:], payload.TreeSize)
	framed, err := frameDomain(DomainAnchorID,
		[]byte(payload.CryptoSuite), []byte(payload.TreeAlgorithm), []byte(payload.NodeID), []byte(payload.LogID),
		[]byte(payload.SinkName), payload.StreamID, treeSize[:], []byte(payload.RootHashAlgorithm), payload.RootHash,
		[]byte(payload.STHDigestAlgorithm), payload.SignedSTHDigest)
	if err != nil {
		return nil, err
	}
	return protocolDigestForSuite(payload.CryptoSuite, framed)
}

func protocolDigestForSuite(suiteID cryptosuite.ID, data []byte) ([]byte, error) {
	suite, err := cryptosuite.RequireKnown(suiteID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPayload, err)
	}
	digest, err := trustcrypto.HashBytesForSuite(suiteID, suite.AnchorDigest.Algorithm, data)
	if err != nil {
		return nil, fmt.Errorf("%w: hash domain frame: %v", ErrInvalidPayload, err)
	}
	return digest, nil
}

func frameDomain(domain string, fields ...[]byte) ([]byte, error) {
	if len(domain) == 0 || len(domain) > math.MaxUint16 || len(fields) > math.MaxUint16 {
		return nil, fmt.Errorf("%w: invalid domain frame", ErrInvalidPayload)
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(domain)))
	buf.WriteString(domain)
	_ = binary.Write(&buf, binary.BigEndian, uint16(len(fields)))
	for _, field := range fields {
		if len(field) > math.MaxUint32 {
			return nil, fmt.Errorf("%w: domain field exceeds uint32 length", ErrInvalidPayload)
		}
		_ = binary.Write(&buf, binary.BigEndian, uint32(len(field)))
		buf.Write(field)
	}
	return buf.Bytes(), nil
}

func writeLP16(w io.Writer, value []byte) error {
	if len(value) > maxPayloadField || len(value) > math.MaxUint16 {
		return fmt.Errorf("%w: field length %d exceeds %d", ErrInvalidPayload, len(value), maxPayloadField)
	}
	if err := binary.Write(w, binary.BigEndian, uint16(len(value))); err != nil {
		return fmt.Errorf("%w: write length: %v", ErrInvalidPayload, err)
	}
	if _, err := w.Write(value); err != nil {
		return fmt.Errorf("%w: write field: %v", ErrInvalidPayload, err)
	}
	return nil
}

func readLP16(r *bytes.Reader) ([]byte, error) {
	var size uint16
	if err := binary.Read(r, binary.BigEndian, &size); err != nil {
		return nil, fmt.Errorf("%w: read field length: %v", ErrInvalidPayload, err)
	}
	if int(size) > maxPayloadField || int(size) > r.Len() {
		return nil, fmt.Errorf("%w: invalid field length %d", ErrInvalidPayload, size)
	}
	value := make([]byte, int(size))
	if _, err := io.ReadFull(r, value); err != nil {
		return nil, fmt.Errorf("%w: read field: %v", ErrInvalidPayload, err)
	}
	return value, nil
}
