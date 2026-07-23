package smconformance

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/emmansun/gmsm/sm4"
	"github.com/emmansun/gmsm/smx509"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
	"github.com/wowtrust/trustdb/internal/trustcrypto"
)

const (
	wantSchema = "trustdb.sm.conformance-v1"
	wantSuite  = "CN_SM_V1"
)

type vectorFile struct {
	Schema    string       `json:"schema"`
	Suite     string       `json:"suite"`
	Sources   []string     `json:"sources"`
	SM2       sm2Vector    `json:"sm2"`
	SM3       []sm3Vector  `json:"sm3"`
	MerkleSM3 merkleVector `json:"merkle_sm3"`
	SM4       sm4Vectors   `json:"sm4"`
}

type sm2Vector struct {
	UserIDASCII              string `json:"user_id_ascii"`
	PrivateKeyHex            string `json:"private_key_hex"`
	PublicKeyUncompressedHex string `json:"public_key_uncompressed_hex"`
	MessageUTF8              string `json:"message_utf8"`
	EphemeralKHex            string `json:"ephemeral_k_hex"`
	ZAHex                    string `json:"za_hex"`
	MessageDigestHex         string `json:"message_digest_hex"`
	SignatureEncoding        string `json:"signature_encoding"`
	SignatureDERHex          string `json:"signature_der_hex"`
}

type sm3Vector struct {
	ID           string `json:"id"`
	MessageASCII string `json:"message_ascii"`
	Repeat       int    `json:"repeat"`
	DigestHex    string `json:"digest_hex"`
}

type merkleVector struct {
	LeafPrefixHex  string       `json:"leaf_prefix_hex"`
	NodePrefixHex  string       `json:"node_prefix_hex"`
	EmptyRootHex   string       `json:"empty_root_hex"`
	Leaves         []merkleLeaf `json:"leaves"`
	TwoLeafRootHex string       `json:"two_leaf_root_hex"`
}

type merkleLeaf struct {
	PayloadUTF8 string `json:"payload_utf8"`
	HashHex     string `json:"hash_hex"`
}

type sm4Vectors struct {
	Block    sm4BlockVector    `json:"block"`
	Envelope sm4EnvelopeVector `json:"envelope"`
}

type sm4BlockVector struct {
	KeyHex                         string `json:"key_hex"`
	PlaintextHex                   string `json:"plaintext_hex"`
	CiphertextHex                  string `json:"ciphertext_hex"`
	MillionIterationsCiphertextHex string `json:"million_iterations_ciphertext_hex"`
}

type sm4EnvelopeVector struct {
	Algorithm            string   `json:"algorithm"`
	NonceBytes           int      `json:"nonce_bytes"`
	TagBytes             int      `json:"tag_bytes"`
	NonceUniquePerKey    bool     `json:"nonce_unique_per_key"`
	KeyHex               string   `json:"key_hex"`
	NonceHex             string   `json:"nonce_hex"`
	AADLengthPrefixBytes int      `json:"aad_length_prefix_bytes"`
	AADFieldsUTF8        []string `json:"aad_fields_utf8"`
	AADHex               string   `json:"aad_hex"`
	PlaintextUTF8        string   `json:"plaintext_utf8"`
	SealedHex            string   `json:"sealed_hex"`
}

func TestCanonicalVectorMetadata(t *testing.T) {
	v := loadVectors(t)
	if v.Schema != wantSchema || v.Suite != wantSuite {
		t.Fatalf("vector identity = (%q, %q), want (%q, %q)", v.Schema, v.Suite, wantSchema, wantSuite)
	}
	if len(v.Sources) < 5 {
		t.Fatalf("sources = %d, want at least 5 independent standard/source references", len(v.Sources))
	}
	if v.SM2.SignatureEncoding != "ASN.1 DER SEQUENCE(INTEGER r, INTEGER s)" {
		t.Fatalf("unexpected SM2 signature encoding %q", v.SM2.SignatureEncoding)
	}
	if v.SM2.EphemeralKHex == "" {
		t.Fatal("official SM2 nonce is missing from the published vector")
	}
}

func TestSM3KnownAnswersAndStreaming(t *testing.T) {
	v := loadVectors(t)
	for _, tc := range v.SM3 {
		t.Run(tc.ID, func(t *testing.T) {
			message := bytes.Repeat([]byte(tc.MessageASCII), tc.Repeat)
			want := decodeHex(t, tc.DigestHex)
			digest := sm3.Sum(message)
			if !bytes.Equal(digest[:], want) {
				t.Fatalf("one-shot digest = %x, want %x", digest, want)
			}

			stream := sm3.New()
			for offset, width := 0, 1; offset < len(message); width++ {
				end := min(offset+width, len(message))
				if _, err := stream.Write(message[offset:end]); err != nil {
					t.Fatalf("stream.Write: %v", err)
				}
				offset = end
			}
			if got := stream.Sum(nil); !bytes.Equal(got, want) {
				t.Fatalf("streaming digest = %x, want %x", got, want)
			}
		})
	}
}

func TestRFC6962SM3DomainVectors(t *testing.T) {
	v := loadVectors(t).MerkleSM3
	leafPrefix := decodeSingleByte(t, v.LeafPrefixHex)
	nodePrefix := decodeSingleByte(t, v.NodePrefixHex)
	if leafPrefix != 0x00 || nodePrefix != 0x01 {
		t.Fatalf("Merkle prefixes = (%#x, %#x), want (0x00, 0x01)", leafPrefix, nodePrefix)
	}

	empty := sm3.Sum(nil)
	if want := decodeHex(t, v.EmptyRootHex); !bytes.Equal(empty[:], want) {
		t.Fatalf("empty root = %x, want %x", empty, want)
	}
	if len(v.Leaves) != 2 {
		t.Fatalf("leaf count = %d, want 2", len(v.Leaves))
	}

	leaves := make([][]byte, len(v.Leaves))
	for i, tc := range v.Leaves {
		input := append([]byte{leafPrefix}, []byte(tc.PayloadUTF8)...)
		digest := sm3.Sum(input)
		leaves[i] = append([]byte(nil), digest[:]...)
		if want := decodeHex(t, tc.HashHex); !bytes.Equal(leaves[i], want) {
			t.Fatalf("leaf %d hash = %x, want %x", i, leaves[i], want)
		}
	}

	nodeInput := make([]byte, 1, 1+2*sm3.Size)
	nodeInput[0] = nodePrefix
	nodeInput = append(nodeInput, leaves[0]...)
	nodeInput = append(nodeInput, leaves[1]...)
	root := sm3.Sum(nodeInput)
	if want := decodeHex(t, v.TwoLeafRootHex); !bytes.Equal(root[:], want) {
		t.Fatalf("two-leaf root = %x, want %x", root, want)
	}
}

func TestSM2OfficialSignatureVector(t *testing.T) {
	v := loadVectors(t).SM2
	privateKey, err := sm2.NewPrivateKey(decodeHex(t, v.PrivateKeyHex))
	if err != nil {
		t.Fatalf("sm2.NewPrivateKey: %v", err)
	}
	derivedPublic := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
	wantPublic := decodeHex(t, v.PublicKeyUncompressedHex)
	if !bytes.Equal(derivedPublic, wantPublic) {
		t.Fatalf("derived public key = %x, want %x", derivedPublic, wantPublic)
	}

	publicKey, err := sm2.ParseUncompressedPublicKey(wantPublic)
	if err != nil {
		t.Fatalf("sm2.ParseUncompressedPublicKey: %v", err)
	}
	uid := []byte(v.UserIDASCII)
	za, err := sm2.CalculateZA(publicKey, uid)
	if err != nil {
		t.Fatalf("sm2.CalculateZA: %v", err)
	}
	if want := decodeHex(t, v.ZAHex); !bytes.Equal(za, want) {
		t.Fatalf("ZA = %x, want %x", za, want)
	}
	defaultZA, err := sm2.CalculateZA(publicKey, nil)
	if err != nil {
		t.Fatalf("sm2.CalculateZA with default user ID: %v", err)
	}
	if !bytes.Equal(defaultZA, za) {
		t.Fatalf("default user-ID ZA = %x, explicit canonical ZA = %x", defaultZA, za)
	}

	h := sm3.New()
	h.Write(za)
	h.Write([]byte(v.MessageUTF8))
	digest := h.Sum(nil)
	if want := decodeHex(t, v.MessageDigestHex); !bytes.Equal(digest, want) {
		t.Fatalf("SM3(ZA || message) = %x, want %x", digest, want)
	}
	signature := decodeHex(t, v.SignatureDERHex)
	descriptor, err := trustcrypto.NewSM2PublicKey("official-vector", wantPublic)
	if err != nil {
		t.Fatalf("trustcrypto.NewSM2PublicKey: %v", err)
	}
	if err := trustcrypto.VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, []byte(v.MessageUTF8), model.Signature{
		Alg: cryptosuite.SignatureSM2SM3, KeyID: descriptor.KeyID, Signature: signature,
	}); err != nil {
		t.Fatalf("TrustDB SM2 provider rejected official signature: %v", err)
	}
	if !sm2.VerifyASN1WithSM2(publicKey, uid, []byte(v.MessageUTF8), signature) {
		t.Fatal("official SM2 signature did not verify")
	}
	if !sm2.VerifyASN1WithSM2(publicKey, nil, []byte(v.MessageUTF8), signature) {
		t.Fatal("official SM2 signature did not verify with the canonical default user ID")
	}
	if sm2.VerifyASN1WithSM2(publicKey, []byte("wrong-user-id"), []byte(v.MessageUTF8), signature) {
		t.Fatal("SM2 signature verified with a different user ID")
	}
	if sm2.VerifyASN1WithSM2(publicKey, uid, []byte(v.MessageUTF8+"!"), signature) {
		t.Fatal("SM2 signature verified with a modified message")
	}
	if sm2.VerifyASN1WithSM2(publicKey, uid, []byte(v.MessageUTF8), append(signature, 0x00)) {
		t.Fatal("SM2 verifier accepted trailing data after DER signature")
	}
	rawRS := append(decodeHex(t, "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3"),
		decodeHex(t, "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa")...)
	if sm2.VerifyASN1WithSM2(publicKey, uid, []byte(v.MessageUTF8), rawRS) {
		t.Fatal("SM2 verifier accepted raw r || s instead of strict DER")
	}
}

func TestSM4KnownAnswers(t *testing.T) {
	v := loadVectors(t).SM4.Block
	block, err := sm4.NewCipher(decodeHex(t, v.KeyHex))
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	plaintext := decodeHex(t, v.PlaintextHex)
	got := make([]byte, block.BlockSize())
	block.Encrypt(got, plaintext)
	if want := decodeHex(t, v.CiphertextHex); !bytes.Equal(got, want) {
		t.Fatalf("single-block ciphertext = %x, want %x", got, want)
	}

	state := append([]byte(nil), plaintext...)
	for range 1_000_000 {
		block.Encrypt(state, state)
	}
	if want := decodeHex(t, v.MillionIterationsCiphertextHex); !bytes.Equal(state, want) {
		t.Fatalf("million-iteration ciphertext = %x, want %x", state, want)
	}
}

func TestSM4GCMEnvelopeVector(t *testing.T) {
	v := loadVectors(t).SM4.Envelope
	if v.Algorithm != "SM4-GCM" || v.NonceBytes != 12 || v.TagBytes != 16 || !v.NonceUniquePerKey {
		t.Fatalf("unsafe or unexpected envelope parameters: %#v", v)
	}
	if v.AADLengthPrefixBytes != 2 {
		t.Fatalf("AAD length prefix = %d, want 2", v.AADLengthPrefixBytes)
	}
	aad := frameAAD(t, v.AADFieldsUTF8)
	if want := decodeHex(t, v.AADHex); !bytes.Equal(aad, want) {
		t.Fatalf("AAD = %x, want %x", aad, want)
	}

	block, err := sm4.NewCipher(decodeHex(t, v.KeyHex))
	if err != nil {
		t.Fatalf("sm4.NewCipher: %v", err)
	}
	aead, err := newGCM(block, v.NonceBytes, v.TagBytes)
	if err != nil {
		t.Fatalf("newGCM: %v", err)
	}
	nonce := decodeHex(t, v.NonceHex)
	sealed := aead.Seal(nil, nonce, []byte(v.PlaintextUTF8), aad)
	if want := decodeHex(t, v.SealedHex); !bytes.Equal(sealed, want) {
		t.Fatalf("sealed envelope = %x, want %x", sealed, want)
	}
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open canonical envelope: %v", err)
	}
	if !bytes.Equal(opened, []byte(v.PlaintextUTF8)) {
		t.Fatalf("opened plaintext = %q, want %q", opened, v.PlaintextUTF8)
	}
	if _, err := aead.Open(nil, nonce, sealed, append(aad, 0x00)); err == nil {
		t.Fatal("SM4-GCM accepted modified AAD")
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := aead.Open(nil, nonce, tampered, aad); err == nil {
		t.Fatal("SM4-GCM accepted a modified authentication tag")
	}
}

func TestIndependentOpenSSLOracle(t *testing.T) {
	path, err := exec.LookPath("openssl")
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("OpenSSL executable is required by the CI conformance gate: %v", err)
		}
		t.Skip("OpenSSL/LibreSSL executable not installed")
	}
	v := loadVectors(t)

	t.Run("SM2", func(t *testing.T) {
		publicKey, err := sm2.NewPublicKey(decodeHex(t, v.SM2.PublicKeyUncompressedHex))
		if err != nil {
			t.Fatal(err)
		}
		publicDER, err := smx509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		publicPath := filepath.Join(dir, "sm2-public.pem")
		signaturePath := filepath.Join(dir, "sm2-signature.der")
		if err := os.WriteFile(publicPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(signaturePath, decodeHex(t, v.SM2.SignatureDERHex), 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := runOpenSSL(path, []byte(v.SM2.MessageUTF8),
			"dgst", "-sm3", "-verify", publicPath, "-signature", signaturePath,
			"-sigopt", "distid:"+v.SM2.UserIDASCII)
		if err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("OpenSSL SM2 is required by the CI conformance gate: %v", err)
			}
			t.Skipf("OpenSSL/LibreSSL SM2 unavailable: %v", err)
		}
		if !strings.Contains(string(output), "Verified OK") {
			t.Fatalf("OpenSSL SM2 output = %q", output)
		}
		if _, err := runOpenSSL(path, []byte(v.SM2.MessageUTF8),
			"dgst", "-sm3", "-verify", publicPath, "-signature", signaturePath,
			"-sigopt", "distid:wrong-user-id"); err == nil {
			t.Fatal("OpenSSL SM2 accepted the wrong user ID")
		}
	})

	t.Run("SM3", func(t *testing.T) {
		for _, tc := range v.SM3 {
			message := bytes.Repeat([]byte(tc.MessageASCII), tc.Repeat)
			got, err := runOpenSSL(path, message, "dgst", "-sm3", "-binary")
			if err != nil {
				if os.Getenv("CI") != "" {
					t.Fatalf("OpenSSL SM3 is required by the CI conformance gate: %v", err)
				}
				t.Skipf("OpenSSL/LibreSSL SM3 unavailable: %v", err)
			}
			if want := decodeHex(t, tc.DigestHex); !bytes.Equal(got, want) {
				t.Fatalf("OpenSSL/LibreSSL digest for %s = %x, want %x", tc.ID, got, want)
			}
		}
	})

	t.Run("SM4", func(t *testing.T) {
		tc := v.SM4.Block
		got, err := runOpenSSL(path, decodeHex(t, tc.PlaintextHex),
			"enc", "-sm4-ecb", "-K", tc.KeyHex, "-nopad")
		if err != nil {
			if os.Getenv("CI") != "" {
				t.Fatalf("OpenSSL SM4 is required by the CI conformance gate: %v", err)
			}
			t.Skipf("OpenSSL/LibreSSL SM4 unavailable: %v", err)
		}
		if want := decodeHex(t, tc.CiphertextHex); !bytes.Equal(got, want) {
			t.Fatalf("OpenSSL/LibreSSL ciphertext = %x, want %x", got, want)
		}
	})
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "test", "vectors", "cn-sm-v1-conformance.json")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	decoder := json.NewDecoder(f)
	decoder.DisallowUnknownFields()
	var v vectorFile
	if err := decoder.Decode(&v); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatalf("decode %s: trailing data: %v", path, err)
	}
	return v
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex %q: %v", value, err)
	}
	return decoded
}

func decodeSingleByte(t *testing.T, value string) byte {
	t.Helper()
	decoded := decodeHex(t, value)
	if len(decoded) != 1 {
		t.Fatalf("decoded %q to %d bytes, want 1", value, len(decoded))
	}
	return decoded[0]
}

func frameAAD(t *testing.T, fields []string) []byte {
	t.Helper()
	var out []byte
	for _, field := range fields {
		if len(field) > int(^uint16(0)) {
			t.Fatalf("AAD field length %d exceeds uint16", len(field))
		}
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(field)))
		out = append(out, length[:]...)
		out = append(out, field...)
	}
	return out
}

func newGCM(block cipher.Block, nonceBytes, tagBytes int) (cipher.AEAD, error) {
	if nonceBytes != 12 {
		return nil, fmt.Errorf("unsupported nonce size %d", nonceBytes)
	}
	return cipher.NewGCMWithTagSize(block, tagBytes)
}

func runOpenSSL(path string, input []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w: %s", path, args, err, strings.TrimSpace(stderr.String()))
	}
	return output, nil
}
