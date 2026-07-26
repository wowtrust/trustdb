package backup

import (
	"bufio"
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"

	"github.com/wowtrust/trustdb/v2/internal/cborx"
	"github.com/wowtrust/trustdb/v2/internal/cryptosuite"
	"github.com/wowtrust/trustdb/v2/internal/formatregistry"
	"github.com/wowtrust/trustdb/v2/internal/keyenvelope"
	"github.com/wowtrust/trustdb/v2/internal/proofstoremeta"
	"github.com/wowtrust/trustdb/v2/internal/trusterr"
)

const (
	backupMagic                 = "TRUSTDB-TDBACKUP-V5\x00"
	backupEnvelopeSchema        = "trustdb.backup-envelope.v1"
	backupContentAlgorithm      = "SM4-GCM-FRAMED-V1"
	backupHeaderDigest          = cryptosuite.HashSM3
	defaultFramePlainBytes      = 1 << 20
	minFramePlainBytes          = 64 << 10
	maxFramePlainBytes          = 16 << 20
	maxBackupHeaderBytes        = 64 << 10
	backupDEKBytes              = 16
	backupNoncePrefixBytes      = 8
	backupNonceBytes            = 12
	backupTagBytes              = 16
	backupFrameHeaderBytes      = 9
	backupFrameFinal       byte = 1
)

var errBackupAuthentication = errors.New("backup authentication failed")

// EnvelopeHeader is the cleartext but authenticated routing header. It holds
// only public namespace identity and an opaque wrapped DEK; secret KEKs,
// provider credentials, and private keys never enter the archive.
type EnvelopeHeader struct {
	SchemaVersion       string                 `cbor:"schema_version" json:"schema_version"`
	ArchiveSchema       string                 `cbor:"archive_schema" json:"archive_schema"`
	BackupID            string                 `cbor:"backup_id" json:"backup_id"`
	CreatedAt           string                 `cbor:"created_at" json:"created_at"`
	Compression         string                 `cbor:"compression" json:"compression"`
	CryptoSuite         cryptosuite.ID         `cbor:"crypto_suite" json:"crypto_suite"`
	FormatGeneration    uint64                 `cbor:"format_generation" json:"format_generation"`
	NodeID              string                 `cbor:"node_id" json:"node_id"`
	LogID               string                 `cbor:"log_id" json:"log_id"`
	NamespaceID         string                 `cbor:"namespace_id" json:"namespace_id"`
	ContentAlgorithm    string                 `cbor:"content_algorithm" json:"content_algorithm"`
	HeaderDigest        string                 `cbor:"header_digest" json:"header_digest"`
	FramePlaintextBytes uint32                 `cbor:"frame_plaintext_bytes" json:"frame_plaintext_bytes"`
	NoncePrefix         []byte                 `cbor:"nonce_prefix" json:"nonce_prefix"`
	KEKProvider         string                 `cbor:"kek_provider" json:"kek_provider"`
	KEKKeyID            string                 `cbor:"kek_key_id" json:"kek_key_id"`
	WrappedDEK          keyenvelope.WrappedDEK `cbor:"wrapped_dek" json:"wrapped_dek"`
}

type envelopeAAD struct {
	SchemaVersion       string         `cbor:"schema_version"`
	ArchiveSchema       string         `cbor:"archive_schema"`
	BackupID            string         `cbor:"backup_id"`
	CreatedAt           string         `cbor:"created_at"`
	Compression         string         `cbor:"compression"`
	CryptoSuite         cryptosuite.ID `cbor:"crypto_suite"`
	FormatGeneration    uint64         `cbor:"format_generation"`
	NodeID              string         `cbor:"node_id"`
	LogID               string         `cbor:"log_id"`
	NamespaceID         string         `cbor:"namespace_id"`
	ContentAlgorithm    string         `cbor:"content_algorithm"`
	HeaderDigest        string         `cbor:"header_digest"`
	FramePlaintextBytes uint32         `cbor:"frame_plaintext_bytes"`
	NoncePrefix         []byte         `cbor:"nonce_prefix"`
	KEKProvider         string         `cbor:"kek_provider"`
	KEKKeyID            string         `cbor:"kek_key_id"`
}

func newEncryptedArchiveWriter(ctx context.Context, dst io.Writer, header EnvelopeHeader, provider keyenvelope.KEKProvider, random io.Reader) (*frameWriter, EnvelopeHeader, error) {
	if dst == nil || provider == nil {
		return nil, EnvelopeHeader{}, trusterr.New(trusterr.CodeInvalidArgument, "backup writer and KEK provider are required")
	}
	if random == nil {
		random = rand.Reader
	}
	if header.FramePlaintextBytes == 0 {
		header.FramePlaintextBytes = defaultFramePlainBytes
	}
	header.SchemaVersion = backupEnvelopeSchema
	header.ArchiveSchema = SchemaManifest
	header.ContentAlgorithm = backupContentAlgorithm
	header.HeaderDigest = backupHeaderDigest
	header.KEKProvider = provider.Name()
	header.NoncePrefix = make([]byte, backupNoncePrefixBytes)
	if err := validateEnvelopeHeader(header, false); err != nil {
		return nil, EnvelopeHeader{}, err
	}
	dek := make([]byte, backupDEKBytes)
	defer clearSecret(dek)
	if _, err := io.ReadFull(random, dek); err != nil {
		return nil, EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeInternal, "generate backup DEK", err)
	}
	if _, err := io.ReadFull(random, header.NoncePrefix); err != nil {
		return nil, EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeInternal, "generate backup nonce prefix", err)
	}
	aad, err := marshalEnvelopeAAD(header)
	if err != nil {
		return nil, EnvelopeHeader{}, err
	}
	header.WrappedDEK, err = provider.WrapDEK(ctx, dek, aad)
	if err != nil {
		return nil, EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeFailedPrecondition, "wrap backup DEK", err)
	}
	if err := validateEnvelopeHeader(header, true); err != nil {
		return nil, EnvelopeHeader{}, err
	}
	headerBytes, err := cborx.Marshal(header)
	if err != nil {
		return nil, EnvelopeHeader{}, trusterr.Wrap(trusterr.CodeInternal, "encode backup envelope header", err)
	}
	if len(headerBytes) > maxBackupHeaderBytes {
		return nil, EnvelopeHeader{}, trusterr.New(trusterr.CodeInvalidArgument, "backup envelope header is too large")
	}
	if _, err := io.WriteString(dst, backupMagic); err != nil {
		return nil, EnvelopeHeader{}, err
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(headerBytes)))
	if _, err := dst.Write(length[:]); err != nil {
		return nil, EnvelopeHeader{}, err
	}
	if _, err := dst.Write(headerBytes); err != nil {
		return nil, EnvelopeHeader{}, err
	}
	aead, err := newBackupAEAD(dek)
	if err != nil {
		return nil, EnvelopeHeader{}, err
	}
	digest := sm3.Sum(headerBytes)
	return &frameWriter{
		dst:          dst,
		aead:         aead,
		noncePrefix:  append([]byte(nil), header.NoncePrefix...),
		headerDigest: digest,
		chunk:        make([]byte, 0, int(header.FramePlaintextBytes)),
		maxPlain:     int(header.FramePlaintextBytes),
	}, header, nil
}

type encryptedArchiveReader struct {
	file   io.ReadCloser
	header EnvelopeHeader
	frames *frameReader
}

func openEncryptedArchive(ctx context.Context, path string, providers []keyenvelope.KEKProvider) (*encryptedArchiveReader, error) {
	file, err := openBackupFile(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*encryptedArchiveReader, error) {
		_ = file.Close()
		return nil, err
	}
	reader := bufio.NewReaderSize(file, len(backupMagic)+4)
	magic := make([]byte, len(backupMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != backupMagic {
		return fail(trusterr.New(trusterr.CodeFailedPrecondition, "unsupported backup format: expected encrypted .tdbackup v5"))
	}
	var length [4]byte
	if _, err := io.ReadFull(reader, length[:]); err != nil {
		return fail(trusterr.Wrap(trusterr.CodeDataLoss, "read backup envelope header length", err))
	}
	headerLength := binary.BigEndian.Uint32(length[:])
	if headerLength == 0 || headerLength > maxBackupHeaderBytes {
		return fail(trusterr.New(trusterr.CodeDataLoss, "backup envelope header length is invalid"))
	}
	headerBytes := make([]byte, int(headerLength))
	if _, err := io.ReadFull(reader, headerBytes); err != nil {
		return fail(trusterr.Wrap(trusterr.CodeDataLoss, "read backup envelope header", err))
	}
	var header EnvelopeHeader
	if err := cborx.UnmarshalLimit(headerBytes, &header, maxBackupHeaderBytes); err != nil {
		return fail(trusterr.Wrap(trusterr.CodeDataLoss, "decode backup envelope header", err))
	}
	canonical, err := cborx.Marshal(header)
	if err != nil || !bytes.Equal(canonical, headerBytes) {
		return fail(trusterr.New(trusterr.CodeDataLoss, "backup envelope header is not deterministic CBOR"))
	}
	if err := validateEnvelopeHeader(header, true); err != nil {
		return fail(err)
	}
	provider, err := selectKEKProvider(header.KEKProvider, providers)
	if err != nil {
		return fail(err)
	}
	aad, err := marshalEnvelopeAAD(header)
	if err != nil {
		return fail(err)
	}
	dek, err := provider.UnwrapDEK(ctx, header.WrappedDEK, aad)
	if err != nil || len(dek) != backupDEKBytes {
		clearSecret(dek)
		return fail(trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error()))
	}
	defer clearSecret(dek)
	aead, err := newBackupAEAD(dek)
	if err != nil {
		return fail(err)
	}
	digest := sm3.Sum(headerBytes)
	frames := &frameReader{
		src:          reader,
		aead:         aead,
		noncePrefix:  append([]byte(nil), header.NoncePrefix...),
		headerDigest: digest,
		maxPlain:     int(header.FramePlaintextBytes),
	}
	return &encryptedArchiveReader{file: file, header: header, frames: frames}, nil
}

func (r *encryptedArchiveReader) Close() error { return r.file.Close() }

func openBackupFile(path string) (io.ReadCloser, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, trusterr.Wrap(trusterr.CodeInternal, "open backup file", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, trusterr.Wrap(trusterr.CodeInternal, "stat backup file", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, trusterr.New(trusterr.CodeInvalidArgument, "backup path is not a regular file")
	}
	return file, nil
}

func requireBackupV5(suiteID cryptosuite.ID) (formatregistry.Descriptor, cryptosuite.Suite, error) {
	descriptor, suite, err := formatregistry.RequireWritable(formatregistry.BackupV5, suiteID)
	if err != nil {
		return formatregistry.Descriptor{}, cryptosuite.Suite{}, trusterr.Wrap(trusterr.CodeFailedPrecondition, "backup v5 is not writable for this cryptographic suite", err)
	}
	return descriptor, suite, nil
}

func marshalEnvelopeAAD(header EnvelopeHeader) ([]byte, error) {
	return cborx.Marshal(envelopeAAD{
		SchemaVersion:       header.SchemaVersion,
		ArchiveSchema:       header.ArchiveSchema,
		BackupID:            header.BackupID,
		CreatedAt:           header.CreatedAt,
		Compression:         header.Compression,
		CryptoSuite:         header.CryptoSuite,
		FormatGeneration:    header.FormatGeneration,
		NodeID:              header.NodeID,
		LogID:               header.LogID,
		NamespaceID:         header.NamespaceID,
		ContentAlgorithm:    header.ContentAlgorithm,
		HeaderDigest:        header.HeaderDigest,
		FramePlaintextBytes: header.FramePlaintextBytes,
		NoncePrefix:         header.NoncePrefix,
		KEKProvider:         header.KEKProvider,
		KEKKeyID:            header.KEKKeyID,
	})
}

func validateEnvelopeHeader(header EnvelopeHeader, requireWrapped bool) error {
	if header.SchemaVersion != backupEnvelopeSchema || header.ArchiveSchema != SchemaManifest {
		return trusterr.New(trusterr.CodeFailedPrecondition, "unsupported backup envelope schema")
	}
	if header.ContentAlgorithm != backupContentAlgorithm || header.HeaderDigest != backupHeaderDigest {
		return trusterr.New(trusterr.CodeFailedPrecondition, "unsupported backup encryption algorithm")
	}
	if header.FormatGeneration != proofstoremeta.FormatGeneration {
		return trusterr.New(trusterr.CodeFailedPrecondition, "backup format generation does not match proofstore v5")
	}
	if _, _, err := requireBackupV5(header.CryptoSuite); err != nil {
		return err
	}
	if err := proofstoremeta.ValidateIdentity(header.NodeID, header.LogID, header.NamespaceID); err != nil {
		return trusterr.Wrap(trusterr.CodeDataLoss, "backup namespace identity", err)
	}
	if header.BackupID == "" || header.CreatedAt == "" || header.KEKProvider == "" || header.KEKKeyID == "" {
		return trusterr.New(trusterr.CodeDataLoss, "backup envelope identity is incomplete")
	}
	if header.Compression != "gzip" && header.Compression != "none" {
		return trusterr.New(trusterr.CodeFailedPrecondition, "unsupported backup compression")
	}
	if header.FramePlaintextBytes < minFramePlainBytes || header.FramePlaintextBytes > maxFramePlainBytes {
		return trusterr.New(trusterr.CodeDataLoss, "backup frame size is outside policy")
	}
	if len(header.NoncePrefix) != backupNoncePrefixBytes {
		return trusterr.New(trusterr.CodeDataLoss, "backup nonce prefix size is invalid")
	}
	if requireWrapped {
		if header.WrappedDEK.Provider != header.KEKProvider || header.WrappedDEK.Algorithm == "" || len(header.WrappedDEK.Ciphertext) == 0 {
			return trusterr.New(trusterr.CodeDataLoss, "backup wrapped DEK metadata is invalid")
		}
	}
	return nil
}

func selectKEKProvider(name string, providers []keyenvelope.KEKProvider) (keyenvelope.KEKProvider, error) {
	var selected keyenvelope.KEKProvider
	for _, provider := range providers {
		if provider == nil || provider.Name() != name {
			continue
		}
		if selected != nil {
			return nil, trusterr.New(trusterr.CodeInvalidArgument, "duplicate backup KEK provider registration")
		}
		selected = provider
	}
	if selected == nil {
		return nil, trusterr.New(trusterr.CodeFailedPrecondition, "backup KEK provider is not configured")
	}
	return selected, nil
}

func newBackupAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != backupDEKBytes {
		return nil, trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	aead, err := cipher.NewGCMWithTagSize(block, backupTagBytes)
	if err != nil || aead.NonceSize() != backupNonceBytes || aead.Overhead() != backupTagBytes {
		return nil, trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	return aead, nil
}

type frameWriter struct {
	dst          io.Writer
	aead         cipher.AEAD
	noncePrefix  []byte
	headerDigest [32]byte
	chunk        []byte
	maxPlain     int
	ordinal      uint32
	closed       bool
}

func (w *frameWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("backup frame writer is closed")
	}
	written := 0
	for len(p) > 0 {
		space := w.maxPlain - len(w.chunk)
		n := len(p)
		if n > space {
			n = space
		}
		w.chunk = append(w.chunk, p[:n]...)
		p = p[n:]
		written += n
		if len(w.chunk) == w.maxPlain {
			if err := w.writeFrame(w.chunk, 0); err != nil {
				return written, err
			}
			w.chunk = w.chunk[:0]
		}
	}
	return written, nil
}

func (w *frameWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if len(w.chunk) > 0 {
		if err := w.writeFrame(w.chunk, 0); err != nil {
			return err
		}
		w.chunk = nil
	}
	return w.writeFrame(nil, backupFrameFinal)
}

func (w *frameWriter) writeFrame(plaintext []byte, flags byte) error {
	if w.ordinal == ^uint32(0) {
		return trusterr.New(trusterr.CodeResourceExhausted, "backup has too many encrypted frames")
	}
	header := makeFrameHeader(w.ordinal, uint32(len(plaintext)), flags)
	nonce := makeFrameNonce(w.noncePrefix, w.ordinal)
	aad := makeFrameAAD(w.headerDigest, header)
	ciphertext := w.aead.Seal(nil, nonce, plaintext, aad)
	if _, err := w.dst.Write(header[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(ciphertext); err != nil {
		return err
	}
	w.ordinal++
	return nil
}

type frameReader struct {
	src          io.Reader
	aead         cipher.AEAD
	noncePrefix  []byte
	headerDigest [32]byte
	maxPlain     int
	expected     uint32
	plain        []byte
	final        bool
	failed       error
}

func (r *frameReader) Read(p []byte) (int, error) {
	if r.failed != nil {
		return 0, r.failed
	}
	for len(r.plain) == 0 {
		if r.final {
			return 0, io.EOF
		}
		if err := r.readFrame(); err != nil {
			r.failed = err
			return 0, err
		}
	}
	n := copy(p, r.plain)
	r.plain = r.plain[n:]
	return n, nil
}

func (r *frameReader) readFrame() error {
	var header [backupFrameHeaderBytes]byte
	if _, err := io.ReadFull(r.src, header[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return trusterr.New(trusterr.CodeDataLoss, "encrypted backup is truncated before its final frame")
		}
		return err
	}
	ordinal := binary.BigEndian.Uint32(header[0:4])
	plainLength := binary.BigEndian.Uint32(header[4:8])
	flags := header[8]
	if ordinal != r.expected || int(plainLength) > r.maxPlain || flags&^backupFrameFinal != 0 {
		return trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	if flags == backupFrameFinal && plainLength != 0 {
		return trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	ciphertext := make([]byte, int(plainLength)+r.aead.Overhead())
	if _, err := io.ReadFull(r.src, ciphertext); err != nil {
		return trusterr.New(trusterr.CodeDataLoss, "encrypted backup frame is truncated")
	}
	nonce := makeFrameNonce(r.noncePrefix, ordinal)
	aad := makeFrameAAD(r.headerDigest, header)
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, aad)
	clearSecret(ciphertext)
	if err != nil {
		return trusterr.New(trusterr.CodeDataLoss, errBackupAuthentication.Error())
	}
	r.expected++
	if flags == backupFrameFinal {
		var extra [1]byte
		n, err := r.src.Read(extra[:])
		if n != 0 || (err != nil && err != io.EOF) || err == nil {
			clearSecret(plaintext)
			return trusterr.New(trusterr.CodeDataLoss, "encrypted backup has trailing data")
		}
		r.final = true
		clearSecret(plaintext)
		return nil
	}
	r.plain = plaintext
	return nil
}

func makeFrameHeader(ordinal, plainLength uint32, flags byte) [backupFrameHeaderBytes]byte {
	var header [backupFrameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[0:4], ordinal)
	binary.BigEndian.PutUint32(header[4:8], plainLength)
	header[8] = flags
	return header
}

func makeFrameNonce(prefix []byte, ordinal uint32) []byte {
	nonce := make([]byte, backupNonceBytes)
	copy(nonce, prefix)
	binary.BigEndian.PutUint32(nonce[backupNoncePrefixBytes:], ordinal)
	return nonce
}

func makeFrameAAD(headerDigest [32]byte, frameHeader [backupFrameHeaderBytes]byte) []byte {
	aad := make([]byte, 0, len("trustdb.backup-frame.v1")+len(headerDigest)+len(frameHeader))
	aad = append(aad, "trustdb.backup-frame.v1"...)
	aad = append(aad, headerDigest[:]...)
	aad = append(aad, frameHeader[:]...)
	return aad
}

func clearSecret(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
