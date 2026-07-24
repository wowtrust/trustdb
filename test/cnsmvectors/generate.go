package cnsmvectors

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"

	"github.com/wowtrust/trustdb/internal/app"
	"github.com/wowtrust/trustdb/internal/cborx"
	"github.com/wowtrust/trustdb/internal/claim"
	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/globallog"
	"github.com/wowtrust/trustdb/internal/keydescriptor"
	"github.com/wowtrust/trustdb/internal/keystore"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/proofstore"
	"github.com/wowtrust/trustdb/internal/sproof"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
	"github.com/wowtrust/trustdb/internal/verify"
	"github.com/wowtrust/trustdb/internal/wal"
)

const (
	clientPrivateHex   = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	serverPrivateHex   = "2222222222222222222222222222222222222222222222222222222222222222"
	registryPrivateHex = "3333333333333333333333333333333333333333333333333333333333333333"

	vectorNodeID = "node-cn-sm-vector"
	vectorLogID  = "log-cn-sm-vector"
)

type deterministicSM2Signer struct {
	mu         sync.RWMutex
	handle     trustcrypto.KeyHandle
	privateKey *sm2.PrivateKey
	private    []byte
	public     []byte
}

func newDeterministicSM2Signer(keyID, privateHex string) (*deterministicSM2Signer, error) {
	privateKey, err := hex.DecodeString(privateHex)
	if err != nil {
		return nil, err
	}
	parsed, err := sm2.NewPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return &deterministicSM2Signer{
		handle: trustcrypto.KeyHandle{
			Provider:  "cn-sm-vector",
			KeyID:     keyID,
			Algorithm: cryptosuite.SignatureSM2SM3,
		},
		privateKey: parsed,
		private:    append([]byte(nil), privateKey...),
		public:     elliptic.Marshal(sm2.P256(), parsed.X, parsed.Y),
	}, nil
}

func (s *deterministicSM2Signer) Handle() trustcrypto.KeyHandle { return s.handle }

func (*deterministicSM2Signer) Capabilities() trustcrypto.CapabilitySet {
	return trustcrypto.CapabilitySet(trustcrypto.CapabilitySign | trustcrypto.CapabilityPublicKey)
}

func (s *deterministicSM2Signer) PublicKey(ctx context.Context) (trustcrypto.PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return trustcrypto.PublicKeyDescriptor{}, err
	}
	return trustcrypto.NewSM2PublicKey(s.handle.KeyID, s.public)
}

func (s *deterministicSM2Signer) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	seedHash := sm3.New()
	seedHash.Write([]byte("trustdb.cn-sm-v1.vector-nonce.v1"))
	seedHash.Write([]byte{0})
	seedHash.Write(s.private)
	seedHash.Write([]byte{0})
	seedHash.Write(message)
	reader := &sm3CounterReader{seed: seedHash.Sum(nil)}
	signature, err := s.privateKey.SignWithSM2(
		reader,
		[]byte(cryptosuite.SM2DefaultUserID),
		message,
	)
	if err != nil {
		return model.Signature{}, err
	}
	if err := trustcrypto.ValidateSM2SignatureDER(signature); err != nil {
		return model.Signature{}, err
	}
	return model.Signature{
		Alg:       cryptosuite.SignatureSM2SM3,
		KeyID:     s.handle.KeyID,
		Signature: append([]byte(nil), signature...),
	}, nil
}

type sm3CounterReader struct {
	seed    []byte
	counter uint64
	pending []byte
}

func (r *sm3CounterReader) Read(dst []byte) (int, error) {
	written := 0
	for written < len(dst) {
		if len(r.pending) == 0 {
			var counter [8]byte
			binary.BigEndian.PutUint64(counter[:], r.counter)
			r.counter++
			h := sm3.New()
			h.Write(r.seed)
			h.Write(counter[:])
			r.pending = h.Sum(nil)
		}
		count := copy(dst[written:], r.pending)
		r.pending = r.pending[count:]
		written += count
	}
	return written, nil
}

func Generate(workDir string) (Corpus, error) {
	if workDir == "" {
		return Corpus{}, fmt.Errorf("cnsmvectors: work directory is required")
	}
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return Corpus{}, err
	}
	ctx := context.Background()
	provider, err := trustcrypto.ProviderForSuite(cryptosuite.CNSMV1)
	if err != nil {
		return Corpus{}, err
	}
	clientSigner, err := newDeterministicSM2Signer("client-cn-sm-vector", clientPrivateHex)
	if err != nil {
		return Corpus{}, err
	}
	serverSigner, err := newDeterministicSM2Signer("server-cn-sm-vector", serverPrivateHex)
	if err != nil {
		return Corpus{}, err
	}
	registrySigner, err := newDeterministicSM2Signer("registry-cn-sm-vector", registryPrivateHex)
	if err != nil {
		return Corpus{}, err
	}
	clientPublic, _ := clientSigner.PublicKey(ctx)
	serverPublic, _ := serverSigner.PublicKey(ctx)
	registryPublic, _ := registrySigner.PublicKey(ctx)
	clientDescriptor, clientDescriptorBytes, err := publicDescriptor(clientPublic)
	if err != nil {
		return Corpus{}, err
	}
	_, serverDescriptorBytes, err := publicDescriptor(serverPublic)
	if err != nil {
		return Corpus{}, err
	}
	_, registryDescriptorBytes, err := publicDescriptor(registryPublic)
	if err != nil {
		return Corpus{}, err
	}

	contents := [][]byte{
		[]byte("TrustDB CN_SM_V1 interoperability\n"),
		[]byte("secondary batch leaf\n"),
		[]byte("second Global Log batch\n"),
	}
	signedClaims := make([]model.SignedClaim, len(contents))
	for index, content := range contents {
		contentHash, hashErr := trustcrypto.HashBytesWithProvider(provider, cryptosuite.HashSM3, content)
		if hashErr != nil {
			return Corpus{}, hashErr
		}
		unsigned, claimErr := claim.NewFileClaimForSuite(
			cryptosuite.CNSMV1,
			"tenant-cn-sm-vector",
			"client-cn-sm-vector",
			clientPublic.KeyID,
			time.Unix(1_710_000_000+int64(index), int64(index+1)*1_000).UTC(),
			bytes.Repeat([]byte{byte(0x11 + index)}, 16),
			fmt.Sprintf("cn-sm-vector-%d", index+1),
			model.Content{
				HashAlg:       cryptosuite.HashSM3,
				ContentHash:   contentHash,
				ContentLength: int64(len(content)),
				MediaType:     "application/octet-stream",
				StorageURI:    fmt.Sprintf("urn:trustdb:cn-sm-vector:%d", index+1),
			},
			model.Metadata{
				EventType: "interop.created",
				Source:    "cn-sm-vector-generator",
				TraceID:   fmt.Sprintf("trace-cn-sm-vector-%d", index+1),
				Parents:   []string{"parent-z", "parent-a"},
				Custom: map[string]string{
					"z":  "last",
					"a":  "first",
					"语言": "国密",
				},
			},
		)
		if claimErr != nil {
			return Corpus{}, claimErr
		}
		signedClaims[index], err = claim.SignWithProvider(ctx, provider, unsigned, clientSigner)
		if err != nil {
			return Corpus{}, err
		}
	}

	walPath := filepath.Join(workDir, "interop.wal")
	writer, err := wal.OpenWriterWithOptions(walPath, 1, wal.Options{
		CryptoSuite: cryptosuite.CNSMV1,
		NodeID:      vectorNodeID,
		LogID:       vectorLogID,
		NamespaceID: "cn-sm-vector-wal",
	})
	if err != nil {
		return Corpus{}, err
	}
	defer writer.Close()
	engine := app.LocalEngine{
		ServerID:        vectorNodeID,
		LogID:           vectorLogID,
		ServerKeyID:     serverPublic.KeyID,
		ClientPublicKey: clientPublic,
		ServerSigner:    serverSigner,
		CryptoProvider:  provider,
		WAL:             writer,
		Now: func() time.Time {
			return time.Unix(1_710_000_100, 123_456_789).UTC()
		},
	}
	records := make([]model.ServerRecord, len(signedClaims))
	accepted := make([]model.AcceptedReceipt, len(signedClaims))
	for index := range signedClaims {
		records[index], accepted[index], _, err = engine.Submit(ctx, signedClaims[index])
		if err != nil {
			return Corpus{}, err
		}
	}
	primaryCommit, err := engine.ComputeBatch(
		ctx,
		"batch-cn-sm-vector-primary",
		time.Unix(1_710_000_200, 222_000_000).UTC(),
		signedClaims[:2],
		records[:2],
		accepted[:2],
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		return Corpus{}, err
	}
	secondaryCommit, err := engine.ComputeBatch(
		ctx,
		"batch-cn-sm-vector-secondary",
		time.Unix(1_710_000_201, 333_000_000).UTC(),
		signedClaims[2:],
		records[2:],
		accepted[2:],
		model.BatchComputeOptions{Mode: model.BatchComputeMaterialized},
	)
	if err != nil {
		return Corpus{}, err
	}
	if len(primaryCommit.Bundles) != 2 || len(secondaryCommit.Bundles) != 1 {
		return Corpus{}, fmt.Errorf("cnsmvectors: unexpected batch bundle counts")
	}

	store, err := proofstore.OpenLocalStore(
		filepath.Join(workDir, "proofstore"),
		cryptosuite.CNSMV1,
		vectorNodeID,
		vectorLogID,
		"cn-sm-vector-proofstore",
	)
	if err != nil {
		return Corpus{}, err
	}
	defer store.Close()
	global, err := globallog.New(globallog.Options{
		Store:          store,
		NodeID:         vectorNodeID,
		LogID:          vectorLogID,
		Signer:         serverSigner,
		CryptoProvider: provider,
		Clock: func() time.Time {
			return time.Unix(1_710_000_300, 444_000_000).UTC()
		},
	})
	if err != nil {
		return Corpus{}, err
	}
	sths, err := global.AppendBatchRoots(ctx, []model.BatchRoot{primaryCommit.Root, secondaryCommit.Root})
	if err != nil {
		return Corpus{}, err
	}
	if len(sths) != 2 || sths[1].TreeSize != 2 {
		return Corpus{}, fmt.Errorf("cnsmvectors: unexpected STH sequence")
	}
	globalProof, err := global.InclusionProof(ctx, primaryCommit.Root.BatchID, sths[1].TreeSize)
	if err != nil {
		return Corpus{}, err
	}
	globalLeaf, found, err := store.GetGlobalLeafByBatchID(ctx, primaryCommit.Root.BatchID)
	if err != nil || !found {
		return Corpus{}, fmt.Errorf("cnsmvectors: read primary global leaf: found=%v err=%w", found, err)
	}

	registryPath := filepath.Join(workDir, "registry.tdkeys")
	registry, err := keystore.Open(registryPath, registrySigner, registryPublic)
	if err != nil {
		return Corpus{}, err
	}
	keyEvent, err := registry.RegisterClientKey(
		"tenant-cn-sm-vector",
		"client-cn-sm-vector",
		clientDescriptor,
		time.Unix(1_709_999_000, 0).UTC(),
		time.Unix(1_710_100_000, 0).UTC(),
	)
	if err != nil {
		return Corpus{}, err
	}
	registryBytes, err := os.ReadFile(registryPath)
	if err != nil {
		return Corpus{}, err
	}

	identityEvidence := []model.ProofIdentityEvidence{
		{
			SchemaVersion: model.SchemaProofIdentity,
			CryptoSuite:   cryptosuite.CNSMV1,
			Role:          model.ProofIdentityRoleClient,
			KeyID:         clientPublic.KeyID,
			KeyDescriptor: append([]byte(nil), clientDescriptorBytes...),
			RegistryV2:    append([]byte(nil), registryBytes...),
		},
		{
			SchemaVersion: model.SchemaProofIdentity,
			CryptoSuite:   cryptosuite.CNSMV1,
			Role:          model.ProofIdentityRoleServer,
			KeyID:         serverPublic.KeyID,
			KeyDescriptor: append([]byte(nil), serverDescriptorBytes...),
		},
	}
	singleProof, err := sproof.New(primaryCommit.Bundles[0], sproof.Options{
		GlobalProof:      &globalProof,
		IdentityEvidence: identityEvidence,
		ExportedAtUnixN:  time.Unix(1_710_000_400, 555_000_000).UnixNano(),
	})
	if err != nil {
		return Corpus{}, err
	}
	offline, err := sproof.VerifyOffline(bytes.NewReader(contents[0]), singleProof, sproof.OfflineTrust{
		Proof: verify.TrustedKeys{
			ClientPublicKey:         clientPublic,
			ServerPublicKey:         serverPublic,
			SignedTreeHeadPublicKey: serverPublic,
			CryptoProvider:          provider,
		},
		Identity: sproof.IdentityTrust{
			ClientPublicKeys:  []trustcrypto.PublicKeyDescriptor{clientPublic},
			ServerPublicKeys:  []trustcrypto.PublicKeyDescriptor{serverPublic},
			RegistryPublicKey: registryPublic,
			RequireEvidence:   true,
		},
	}, sproof.OfflineOptions{})
	if err != nil || !offline.Valid || offline.ProofLevel != "L4" ||
		offline.ExternalNetworkAccess || offline.ExternalProviderAccess {
		return Corpus{}, fmt.Errorf("cnsmvectors: self-verification result=%+v err=%w", offline, err)
	}

	claimCBOR, err := claim.Canonical(signedClaims[0].Claim)
	if err != nil {
		return Corpus{}, err
	}
	claimInput, err := trustcrypto.SignatureInputForSuite(
		cryptosuite.CNSMV1,
		trustcrypto.SignaturePurposeClientClaim,
		claimCBOR,
	)
	if err != nil {
		return Corpus{}, err
	}
	acceptedInput, err := receiptInput(accepted[0], trustcrypto.SignaturePurposeAcceptedReceipt)
	if err != nil {
		return Corpus{}, err
	}
	committed := primaryCommit.Bundles[0].CommittedReceipt
	committedInput, err := receiptInput(committed, trustcrypto.SignaturePurposeCommittedReceipt)
	if err != nil {
		return Corpus{}, err
	}
	sthInput, err := signedTreeHeadInput(sths[1])
	if err != nil {
		return Corpus{}, err
	}
	keyEventInput, err := keyEventSigningInput(keyEvent)
	if err != nil {
		return Corpus{}, err
	}

	contentVectors := make([]Content, len(contents))
	for index, content := range contents {
		digest := sm3.Sum(content)
		contentVectors[index] = Content{
			ID:        fmt.Sprintf("content-%d", index+1),
			BytesHex:  hex.EncodeToString(content),
			DigestHex: hex.EncodeToString(digest[:]),
		}
	}
	corpus := Corpus{
		Schema:      Schema,
		CryptoSuite: string(cryptosuite.CNSMV1),
		Provenance: Provenance{
			GeneratorVersion:         1,
			GeneratorCommand:         "go run ./test/cnsmvectors/cmd/generate -write",
			CanonicalEncoding:        cryptosuite.CanonicalCBOR,
			SignatureNonceDerivation: "test-only SM3 counter stream over domain, private scalar, and exact signature input",
			SM2UserIDASCII:           cryptosuite.SM2DefaultUserID,
			NetworkRequired:          false,
			Sources: []string{
				"GB/T 32905-2016",
				"GB/T 32918.2-2016",
				"GB/T 32918.5-2017",
				"RFC 8949 deterministic CBOR",
				"RFC 6962 Merkle domain separation adapted to SM3",
				"TrustDB ADR-0006, ADR-0007, and V2 format specifications",
			},
			IndependentOracles: []string{
				"OpenSSL 3 EVP SM2-SM3 verification with distid=1234567812345678",
				"OpenSSL 3 SM3 digest",
			},
		},
		Contents: contentVectors,
		Identities: Identities{
			Client:   identity(clientSigner, clientDescriptorBytes, clientPrivateHex),
			Server:   identity(serverSigner, serverDescriptorBytes, serverPrivateHex),
			Registry: identity(registrySigner, registryDescriptorBytes, registryPrivateHex),
		},
		RecordID: primaryCommit.Bundles[0].RecordID,
		Artifacts: Artifacts{
			ClientClaim:        mustArtifact(signedClaims[0].Claim, claimInput, signedClaims[0].Signature.Signature),
			SignedClaim:        mustArtifact(signedClaims[0], nil, nil),
			ServerRecord:       mustArtifact(records[0], nil, nil),
			AcceptedReceipt:    mustArtifact(accepted[0], acceptedInput, accepted[0].ServerSig.Signature),
			CommittedReceipt:   mustArtifact(committed, committedInput, committed.ServerSig.Signature),
			BatchRoot:          mustArtifact(primaryCommit.Root, nil, nil),
			SecondaryBatchRoot: mustArtifact(secondaryCommit.Root, nil, nil),
			ProofBundle:        mustArtifact(primaryCommit.Bundles[0], nil, nil),
			GlobalLogLeaf:      mustArtifact(globalLeaf, nil, nil),
			SignedTreeHead:     mustArtifact(sths[1], sthInput, sths[1].Signature.Signature),
			GlobalLogProof:     mustArtifact(globalProof, nil, nil),
			SingleProof:        mustArtifact(singleProof, nil, nil),
			KeyEvent:           mustArtifact(keyEvent, keyEventInput, keyEvent.RegistrySignature.Signature),
			KeyRegistryV2: Artifact{
				Encoding: "trustdb.key-registry.v2",
				BytesHex: hex.EncodeToString(registryBytes),
			},
		},
		NegativeCases: []NegativeCase{
			{ID: "cross-suite", Mutation: "change any CN_SM_V1 envelope or trust key to INTL_V1", Expected: "mixed-suite rejection"},
			{ID: "sm2-user-id", Mutation: "verify a corpus signature with an SM2 user ID other than 1234567812345678", Expected: "signature rejection"},
			{ID: "signature-encoding", Mutation: "append a byte to DER or replace DER with raw r||s", Expected: "strict DER rejection"},
			{ID: "embedded-trust-root", Mutation: "omit verifier-local keys while retaining embedded identity evidence", Expected: "missing local trust rejection"},
			{ID: "wrong-trust-root", Mutation: "supply a different SM2 key under the expected KeyID", Expected: "signature or identity binding rejection"},
			{ID: "global-root", Mutation: "flip one bit in the STH root or inclusion path", Expected: "L4 rejection"},
		},
	}
	return corpus, nil
}

func publicDescriptor(public trustcrypto.PublicKeyDescriptor) (keydescriptor.Descriptor, []byte, error) {
	descriptor := keydescriptor.Descriptor{
		SchemaVersion: keydescriptor.SchemaV1,
		Kind:          keydescriptor.KindVerifier,
		Provider:      keydescriptor.ProviderPublic,
		CryptoSuite:   public.Suite,
		KeyID:         public.KeyID,
		Algorithm:     public.Algorithm,
		SM2UserID:     cryptosuite.SM2DefaultUserID,
		PublicKey: keydescriptor.PublicKeyMaterial{
			Encoding: public.Encoding,
			Bytes:    append([]byte(nil), public.Bytes...),
		},
	}
	raw, err := keydescriptor.Marshal(descriptor)
	return descriptor, raw, err
}

func identity(signer *deterministicSM2Signer, descriptor []byte, privateHex string) Identity {
	return Identity{
		KeyID:             signer.handle.KeyID,
		PrivateKeyHex:     privateHex,
		PublicKeyHex:      hex.EncodeToString(signer.public),
		DescriptorCBORHex: hex.EncodeToString(descriptor),
	}
}

func mustArtifact(value any, signingInput, signature []byte) Artifact {
	raw, err := cborx.Marshal(value)
	if err != nil {
		panic(err)
	}
	return Artifact{
		Encoding:          "cbor-core-deterministic-rfc8949",
		BytesHex:          hex.EncodeToString(raw),
		SignatureInputHex: hex.EncodeToString(signingInput),
		SignatureDERHex:   hex.EncodeToString(signature),
	}
}

func receiptInput(value any, purpose trustcrypto.SignaturePurpose) ([]byte, error) {
	switch receipt := value.(type) {
	case model.AcceptedReceipt:
		receipt.ServerSig = model.Signature{}
		payload, err := cborx.Marshal(receipt)
		if err != nil {
			return nil, err
		}
		return trustcrypto.SignatureInputForSuite(cryptosuite.CNSMV1, purpose, payload)
	case model.CommittedReceipt:
		receipt.ServerSig = model.Signature{}
		payload, err := cborx.Marshal(receipt)
		if err != nil {
			return nil, err
		}
		return trustcrypto.SignatureInputForSuite(cryptosuite.CNSMV1, purpose, payload)
	default:
		return nil, fmt.Errorf("cnsmvectors: unsupported receipt type %T", value)
	}
}

func signedTreeHeadInput(sth model.SignedTreeHead) ([]byte, error) {
	sth.Signature = model.Signature{}
	payload, err := cborx.Marshal(sth)
	if err != nil {
		return nil, err
	}
	return trustcrypto.SignatureInputForSuite(
		cryptosuite.CNSMV1,
		trustcrypto.SignaturePurposeSignedTreeHead,
		payload,
	)
}

func keyEventSigningInput(event model.KeyEvent) ([]byte, error) {
	event.RegistrySignature = model.Signature{}
	event.EventHash = nil
	payload, err := cborx.Marshal(event)
	if err != nil {
		return nil, err
	}
	return trustcrypto.SignatureInputForSuite(
		cryptosuite.CNSMV1,
		trustcrypto.SignaturePurposeKeyEvent,
		payload,
	)
}

func CanonicalJSON(corpus Corpus) ([]byte, error) {
	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func Checksum(data []byte) string {
	sum := sha256Sum(data)
	return fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum), CorpusName)
}

func sha256Sum(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

var (
	_ io.Reader          = (*sm3CounterReader)(nil)
	_ trustcrypto.Signer = (*deterministicSM2Signer)(nil)
)
