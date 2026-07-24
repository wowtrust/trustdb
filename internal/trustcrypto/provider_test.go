package trustcrypto

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/wowtrust/trustdb/internal/cryptosuite"
	"github.com/wowtrust/trustdb/internal/model"
)

type fakeProviderSigner struct {
	handle       KeyHandle
	capabilities CapabilitySet
	publicKey    PublicKeyDescriptor
	privateKey   ed25519.PrivateKey
	mutate       func(model.Signature) model.Signature
}

func (s *fakeProviderSigner) Handle() KeyHandle { return s.handle }

func (s *fakeProviderSigner) Capabilities() CapabilitySet { return s.capabilities }

func (s *fakeProviderSigner) PublicKey(ctx context.Context) (PublicKeyDescriptor, error) {
	if err := ctx.Err(); err != nil {
		return PublicKeyDescriptor{}, err
	}
	return s.publicKey.Clone(), nil
}

func (s *fakeProviderSigner) Sign(ctx context.Context, message []byte) (model.Signature, error) {
	if err := ctx.Err(); err != nil {
		return model.Signature{}, err
	}
	sig := model.Signature{
		Alg:       s.handle.Algorithm,
		KeyID:     s.handle.KeyID,
		Signature: ed25519.Sign(s.privateKey, message),
	}
	if s.mutate != nil {
		sig = s.mutate(sig)
	}
	return sig, nil
}

func newFakeProviderSigner(t *testing.T, providerName string) *fakeProviderSigner {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeProviderSigner{
		handle: KeyHandle{
			Provider:  providerName,
			KeyID:     "contract-key",
			Algorithm: cryptosuite.SignatureEd25519,
		},
		capabilities: CapabilitySet(CapabilitySign | CapabilityPublicKey),
		publicKey: PublicKeyDescriptor{
			Suite:     cryptosuite.INTLV1,
			KeyID:     "contract-key",
			Algorithm: cryptosuite.SignatureEd25519,
			Encoding:  cryptosuite.Ed25519PublicKeyEncoding,
			Bytes:     publicKey,
		},
		privateKey: privateKey,
	}
}

func TestSignerProviderContract(t *testing.T) {
	message := []byte("provider-neutral trustdb signing contract")
	for _, providerName := range []string{"software", "remote", "pkcs11", "sdf"} {
		providerName := providerName
		t.Run(providerName, func(t *testing.T) {
			t.Parallel()
			signer := newFakeProviderSigner(t, providerName)
			if err := ValidateSigner(context.Background(), cryptosuite.INTLV1, signer); err != nil {
				t.Fatalf("ValidateSigner() error = %v", err)
			}
			sig, err := Sign(context.Background(), cryptosuite.INTLV1, signer, message)
			if err != nil {
				t.Fatalf("Sign() error = %v", err)
			}
			publicKey, err := signer.PublicKey(context.Background())
			if err != nil {
				t.Fatalf("PublicKey() error = %v", err)
			}
			if err := Verify(context.Background(), DefaultProvider(), publicKey, message, sig); err != nil {
				t.Fatalf("Verify() error = %v", err)
			}
			want := ed25519.Sign(signer.privateKey, message)
			if !bytes.Equal(sig.Signature, want) {
				t.Fatalf("signature changed across provider boundary: got %x want %x", sig.Signature, want)
			}

			// Providers used by batch workers must tolerate concurrent Sign calls.
			var wg sync.WaitGroup
			errs := make(chan error, 32)
			for i := 0; i < cap(errs); i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					input := []byte(fmt.Sprintf("%s-%d", providerName, i))
					sig, err := Sign(context.Background(), cryptosuite.INTLV1, signer, input)
					if err == nil {
						err = Verify(context.Background(), DefaultProvider(), publicKey, input, sig)
					}
					errs <- err
				}(i)
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("concurrent provider contract: %v", err)
				}
			}
		})
	}
}

func TestDestroySignerRevokesSoftwarePrivateKeys(t *testing.T) {
	t.Parallel()
	_, edPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	edSigner, err := NewEd25519Signer("ed-destroy", edPrivate)
	if err != nil {
		t.Fatal(err)
	}
	_, smPrivate, err := GenerateSM2Key()
	if err != nil {
		t.Fatal(err)
	}
	smSigner, err := NewSM2Signer("sm-destroy", smPrivate)
	if err != nil {
		t.Fatal(err)
	}

	for _, signer := range []Signer{edSigner, smSigner} {
		DestroySigner(signer)
		DestroySigner(signer)
		if _, err := signer.Sign(context.Background(), []byte("must fail")); !errors.Is(err, ErrSignerDestroyed) {
			t.Fatalf("%s Sign error = %v, want destroyed", signer.Handle().KeyID, err)
		}
		if _, err := signer.PublicKey(context.Background()); !errors.Is(err, ErrSignerDestroyed) {
			t.Fatalf("%s PublicKey error = %v, want destroyed", signer.Handle().KeyID, err)
		}
	}
}

func TestProviderContractsFailClosed(t *testing.T) {
	t.Parallel()

	t.Run("available CN suite", func(t *testing.T) {
		provider, err := ProviderForSuite(cryptosuite.CNSMV1)
		if err != nil {
			t.Fatalf("ProviderForSuite(CN_SM_V1) error = %v", err)
		}
		if provider.Suite() != cryptosuite.CNSMV1 {
			t.Fatalf("ProviderForSuite(CN_SM_V1) suite = %s", provider.Suite())
		}
	})

	t.Run("missing sign capability", func(t *testing.T) {
		signer := newFakeProviderSigner(t, "remote")
		signer.capabilities = CapabilitySet(CapabilityPublicKey)
		if _, err := Sign(context.Background(), cryptosuite.INTLV1, signer, nil); !errors.Is(err, ErrUnsupportedCapability) {
			t.Fatalf("Sign() error = %v, want unsupported capability", err)
		}
	})

	t.Run("missing public key capability", func(t *testing.T) {
		signer := newFakeProviderSigner(t, "pkcs11")
		signer.capabilities = CapabilitySet(CapabilitySign)
		if err := ValidateSigner(context.Background(), cryptosuite.INTLV1, signer); !errors.Is(err, ErrUnsupportedCapability) {
			t.Fatalf("ValidateSigner() error = %v, want unsupported capability", err)
		}
	})

	t.Run("wrong signer algorithm", func(t *testing.T) {
		signer := newFakeProviderSigner(t, "sdf")
		signer.handle.Algorithm = cryptosuite.SignatureSM2SM3
		if _, err := Sign(context.Background(), cryptosuite.INTLV1, signer, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Fatalf("Sign() error = %v, want unsupported algorithm", err)
		}
	})

	t.Run("provider output metadata", func(t *testing.T) {
		for name, mutate := range map[string]func(model.Signature) model.Signature{
			"algorithm": func(sig model.Signature) model.Signature { sig.Alg = "rsa"; return sig },
			"key id":    func(sig model.Signature) model.Signature { sig.KeyID = "other"; return sig },
			"encoding":  func(sig model.Signature) model.Signature { sig.Signature = sig.Signature[:63]; return sig },
		} {
			name, mutate := name, mutate
			t.Run(name, func(t *testing.T) {
				signer := newFakeProviderSigner(t, "remote")
				signer.mutate = mutate
				if _, err := Sign(context.Background(), cryptosuite.INTLV1, signer, nil); err == nil {
					t.Fatal("Sign() error = nil, want fail-closed provider output rejection")
				}
			})
		}
	})

	t.Run("public key descriptor", func(t *testing.T) {
		signer := newFakeProviderSigner(t, "software")
		descriptor := signer.publicKey
		cases := map[string]func(*PublicKeyDescriptor){
			"suite":     func(d *PublicKeyDescriptor) { d.Suite = cryptosuite.CNSMV1 },
			"algorithm": func(d *PublicKeyDescriptor) { d.Algorithm = cryptosuite.SignatureSM2SM3 },
			"encoding":  func(d *PublicKeyDescriptor) { d.Encoding = cryptosuite.SM2PublicKeyEncoding },
			"length":    func(d *PublicKeyDescriptor) { d.Bytes = d.Bytes[:31] },
		}
		for name, mutate := range cases {
			name, mutate := name, mutate
			t.Run(name, func(t *testing.T) {
				invalid := descriptor.Clone()
				mutate(&invalid)
				if err := ValidatePublicKey(DefaultProvider(), invalid); err == nil {
					t.Fatal("ValidatePublicKey() error = nil, want rejection")
				}
			})
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		signer := newFakeProviderSigner(t, "remote")
		if _, err := Sign(ctx, cryptosuite.INTLV1, signer, nil); !errors.Is(err, context.Canceled) {
			t.Fatalf("Sign() error = %v, want context cancellation", err)
		}
	})
}

func TestINTLV1HashFactoryMatchesGoldenSHA256(t *testing.T) {
	t.Parallel()
	provider := DefaultProvider()
	factory, err := provider.HashFactory(cryptosuite.HashSHA256)
	if err != nil {
		t.Fatal(err)
	}
	got := factory.Sum([]byte("abc"))
	want := []byte{
		0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
		0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
		0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
		0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SHA-256(abc) = %x, want %x", got, want)
	}
	if _, err := provider.HashFactory(cryptosuite.HashSM3); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("HashFactory(sm3) error = %v, want unsupported algorithm", err)
	}
}

func TestCNSMV1HashFactoryMatchesOfficialSM3Vectors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		message []byte
		wantHex string
	}{
		{
			name:    "abc",
			message: []byte("abc"),
			wantHex: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
		},
		{
			name:    "abcd repeated 16 times",
			message: bytes.Repeat([]byte("abcd"), 16),
			wantHex: "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want, err := hex.DecodeString(tc.wantHex)
			if err != nil {
				t.Fatal(err)
			}
			factory, err := HashFactoryForSuite(cryptosuite.CNSMV1, cryptosuite.HashSM3)
			if err != nil {
				t.Fatal(err)
			}
			if factory.Algorithm() != cryptosuite.HashSM3 || factory.Size() != 32 {
				t.Fatalf("factory = (%s, %d)", factory.Algorithm(), factory.Size())
			}
			if got := factory.Sum(tc.message); !bytes.Equal(got, want) {
				t.Fatalf("one-shot SM3 = %x, want %x", got, want)
			}
			got32 := factory.Sum32(tc.message)
			if !bytes.Equal(got32[:], want) {
				t.Fatalf("fixed-width SM3 = %x, want %x", got32, want)
			}
			streamed, n, err := HashReaderForSuite(cryptosuite.CNSMV1, cryptosuite.HashSM3, bytes.NewReader(tc.message))
			if err != nil || n != int64(len(tc.message)) || !bytes.Equal(streamed, want) {
				t.Fatalf("streaming SM3 = %x n=%d err=%v, want %x", streamed, n, err, want)
			}
		})
	}
}

func TestHashFactoryForSuiteRejectsCrossSuiteAlgorithms(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		suite cryptosuite.ID
		alg   string
	}{
		{suite: cryptosuite.INTLV1, alg: cryptosuite.HashSM3},
		{suite: cryptosuite.CNSMV1, alg: cryptosuite.HashSHA256},
		{suite: cryptosuite.ID("UNKNOWN"), alg: cryptosuite.HashSM3},
	} {
		if _, err := HashFactoryForSuite(tc.suite, tc.alg); err == nil {
			t.Fatalf("HashFactoryForSuite(%s, %s) error = nil", tc.suite, tc.alg)
		}
	}
}
