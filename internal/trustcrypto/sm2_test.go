package trustcrypto

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"sync"
	"testing"

	"github.com/emmansun/gmsm/sm2"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

const (
	sm2VectorPrivateKey = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
	sm2VectorPublicKey  = "0409f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13"
	sm2VectorZA         = "b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3"
	sm2VectorSignature  = "3046022100f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3022100b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa"
)

func TestSM2ProviderVerifiesOfficialVector(t *testing.T) {
	t.Parallel()

	publicBytes := mustDecodeHex(t, sm2VectorPublicKey)
	descriptor, err := NewSM2PublicKey("sm2-vector", publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := sm2.NewPublicKey(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	za, err := sm2.CalculateZA(publicKey, []byte(cryptosuite.SM2DefaultUserID))
	if err != nil {
		t.Fatal(err)
	}
	if want := mustDecodeHex(t, sm2VectorZA); !bytes.Equal(za, want) {
		t.Fatalf("ZA = %x, want %x", za, want)
	}
	sig := model.Signature{
		Alg:       cryptosuite.SignatureSM2SM3,
		KeyID:     descriptor.KeyID,
		Signature: mustDecodeHex(t, sm2VectorSignature),
	}
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, []byte("message digest"), sig); err != nil {
		t.Fatalf("Verify() official SM2 vector error = %v", err)
	}

	wrongMessage := append([]byte(nil), []byte("message digest")...)
	wrongMessage[0] ^= 1
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, wrongMessage, sig); err == nil {
		t.Fatal("Verify() accepted a modified message")
	}
	sig.Alg = cryptosuite.SignatureEd25519
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, []byte("message digest"), sig); err == nil {
		t.Fatal("Verify() accepted cross-suite signature metadata")
	}
	sig.Alg = cryptosuite.SignatureSM2SM3
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.INTLV1, descriptor, []byte("message digest"), sig); err == nil {
		t.Fatal("Verify() accepted an SM2 descriptor under INTL_V1")
	}
	wrongKeyID := sig
	wrongKeyID.KeyID = "different-key"
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, []byte("message digest"), wrongKeyID); err == nil {
		t.Fatal("Verify() accepted a mismatched key ID")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifySignatureForSuite(ctx, cryptosuite.CNSMV1, descriptor, []byte("message digest"), sig); err == nil {
		t.Fatal("Verify() accepted a canceled context")
	}
}

func TestSM2SoftwareSignerUsesCanonicalSuitePolicy(t *testing.T) {
	t.Parallel()

	privateBytes := mustDecodeHex(t, sm2VectorPrivateKey)
	signer, err := NewSM2Signer("sm2-key", privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := signer.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := mustDecodeHex(t, sm2VectorPublicKey); !bytes.Equal(descriptor.Bytes, want) {
		t.Fatalf("derived public key = %x, want %x", descriptor.Bytes, want)
	}

	message := []byte("TrustDB canonical SM2-SM3 provider")
	signature, err := signForKnownSuite(context.Background(), cryptosuite.CNSMV1, signer, message)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSM2SignatureDER(signature.Signature); err != nil {
		t.Fatalf("ValidateSM2SignatureDER() error = %v", err)
	}
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, message, signature); err != nil {
		t.Fatalf("Verify() generated signature error = %v", err)
	}
	if _, err := Sign(context.Background(), cryptosuite.CNSMV1, signer, message); !errors.Is(err, cryptosuite.ErrUnavailableSuite) {
		t.Fatalf("production Sign() error = %v, want unavailable suite", err)
	}

	privateKey, err := sm2.NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	wrongUserSignature, err := privateKey.SignWithSM2(rand.Reader, []byte("wrong-user-id"), message)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, message, model.Signature{
		Alg: cryptosuite.SignatureSM2SM3, KeyID: descriptor.KeyID, Signature: wrongUserSignature,
	}); err == nil {
		t.Fatal("Verify() accepted a signature created with a different SM2 user ID")
	}
}

func TestSM2SoftwareSignerIsConcurrent(t *testing.T) {
	t.Parallel()

	signer, err := NewSM2Signer("concurrent-sm2", mustDecodeHex(t, sm2VectorPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := signer.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			message := []byte{byte(i), 0x54, 0x44, 0x42}
			sig, err := signer.Sign(context.Background(), message)
			if err == nil {
				err = VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, message, sig)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SM2 contract error = %v", err)
		}
	}
}

func TestValidateSM2SignatureDERRejectsAmbiguousEncodings(t *testing.T) {
	t.Parallel()

	valid := mustDecodeHex(t, sm2VectorSignature)
	if err := ValidateSM2SignatureDER(valid); err != nil {
		t.Fatalf("official signature error = %v", err)
	}
	outOfRange, err := asn1.Marshal(sm2ASN1Signature{R: new(big.Int).Set(sm2.P256().Params().N), S: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string][]byte{
		"empty":            nil,
		"trailing data":    append(append([]byte(nil), valid...), 0),
		"raw r s":          bytes.Repeat([]byte{1}, 64),
		"zero integer":     {0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01},
		"negative integer": {0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01},
		"non-minimal":      {0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01},
		"out of range":     outOfRange,
	}
	for name, signature := range tests {
		name, signature := name, signature
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := ValidateSM2SignatureDER(signature); err == nil {
				t.Fatal("ValidateSM2SignatureDER() error = nil")
			}
		})
	}
}

func TestSM2PublicKeyDescriptorRejectsWrongCurveAndEncoding(t *testing.T) {
	t.Parallel()

	if _, err := NewSM2PublicKey("sm2", mustDecodeHex(t, sm2VectorPublicKey)); err != nil {
		t.Fatalf("NewSM2PublicKey() official vector error = %v", err)
	}
	wrongCurve := elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy)
	for name, encoded := range map[string][]byte{
		"wrong curve": wrongCurve,
		"compressed":  append([]byte{0x02}, bytes.Repeat([]byte{1}, 32)...),
		"short":       bytes.Repeat([]byte{1}, 64),
	} {
		if _, err := NewSM2PublicKey("sm2", encoded); err == nil {
			t.Fatalf("NewSM2PublicKey() accepted %s", name)
		}
	}
	descriptor, _ := NewSM2PublicKey("sm2", mustDecodeHex(t, sm2VectorPublicKey))
	if err := ValidatePublicKey(DefaultProvider(), descriptor); err == nil {
		t.Fatal("INTL_V1 provider accepted an SM2 public key")
	}
}

func TestSM2ConstructorsRejectInvalidKeysAndCopyPublicBytes(t *testing.T) {
	t.Parallel()

	for name, privateKey := range map[string][]byte{
		"empty": nil,
		"short": bytes.Repeat([]byte{1}, SM2PrivateKeySize-1),
		"zero":  make([]byte, SM2PrivateKeySize),
		"order": sm2.P256().Params().N.FillBytes(make([]byte, SM2PrivateKeySize)),
	} {
		if _, err := NewSM2Signer("sm2", privateKey); err == nil {
			t.Fatalf("NewSM2Signer() accepted %s private key", name)
		}
	}
	if _, err := NewSM2Signer("", mustDecodeHex(t, sm2VectorPrivateKey)); err == nil {
		t.Fatal("NewSM2Signer() accepted an empty key ID")
	}

	encoded := mustDecodeHex(t, sm2VectorPublicKey)
	descriptor, err := NewSM2PublicKey("sm2", encoded)
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] ^= 0xff
	if bytes.Equal(descriptor.Bytes, encoded) {
		t.Fatal("NewSM2PublicKey() retained caller-owned bytes")
	}
}

func FuzzValidateSM2SignatureDER(f *testing.F) {
	f.Add(mustDecodeHex(f, sm2VectorSignature))
	f.Add([]byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01})
	f.Add([]byte{0x30, 0x00})
	f.Fuzz(func(t *testing.T, signature []byte) {
		if len(signature) > 1024 {
			t.Skip()
		}
		if err := ValidateSM2SignatureDER(signature); err != nil {
			return
		}
		var parsed sm2ASN1Signature
		rest, err := asn1.Unmarshal(signature, &parsed)
		if err != nil || len(rest) != 0 {
			t.Fatalf("accepted signature did not strictly decode: rest=%x err=%v", rest, err)
		}
		canonical, err := asn1.Marshal(parsed)
		if err != nil || !bytes.Equal(canonical, signature) {
			t.Fatalf("accepted signature is not canonical: got=%x canonical=%x err=%v", signature, canonical, err)
		}
	})
}

func FuzzSM2VerifierRejectsMalformedInputWithoutPanicking(f *testing.F) {
	publicKey := mustDecodeHex(f, sm2VectorPublicKey)
	f.Add([]byte("message digest"), mustDecodeHex(f, sm2VectorSignature), publicKey)
	f.Add([]byte("message digest"), []byte{0x30, 0x00}, publicKey)
	f.Add([]byte(nil), []byte(nil), []byte(nil))
	f.Fuzz(func(t *testing.T, message, signature, encodedPublicKey []byte) {
		if len(message) > 4096 || len(signature) > 1024 || len(encodedPublicKey) > 1024 {
			t.Skip()
		}
		descriptor := PublicKeyDescriptor{
			Suite: cryptosuite.CNSMV1, KeyID: "fuzz", Algorithm: cryptosuite.SignatureSM2SM3,
			Encoding: cryptosuite.SM2PublicKeyEncoding, Bytes: encodedPublicKey,
		}
		_ = VerifySignatureForSuite(context.Background(), cryptosuite.CNSMV1, descriptor, message, model.Signature{
			Alg: cryptosuite.SignatureSM2SM3, KeyID: "fuzz", Signature: signature,
		})
	})
}

type fataler interface {
	Helper()
	Fatal(...any)
}

func mustDecodeHex(t fataler, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}
