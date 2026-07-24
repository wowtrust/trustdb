package signerplugin

import (
	"bytes"
	"testing"
)

func TestInfoAndBindingValidationFailClosed(t *testing.T) {
	valid := helperInfoResponse()
	if err := ValidateGetInfoResponse(valid); err != nil {
		t.Fatalf("valid info rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*GetInfoResponse)
	}{
		{name: "unknown protocol", mutate: func(info *GetInfoResponse) { info.ProtocolVersion = "future" }},
		{name: "unknown provider", mutate: func(info *GetInfoResponse) { info.ProviderKind = "plugin" }},
		{name: "missing capability", mutate: func(info *GetInfoResponse) { info.Capabilities = []string{CapabilitySign} }},
		{name: "duplicate capability", mutate: func(info *GetInfoResponse) { info.Capabilities = append(info.Capabilities, CapabilitySign) }},
		{name: "unknown capability", mutate: func(info *GetInfoResponse) { info.Capabilities = append(info.Capabilities, "export_private_key") }},
		{name: "unknown suite", mutate: func(info *GetInfoResponse) { info.Algorithms[0].CryptoSuite = "FUTURE" }},
		{name: "wrong encoding", mutate: func(info *GetInfoResponse) { info.Algorithms[0].SignatureEncoding = "raw" }},
		{name: "zero concurrency", mutate: func(info *GetInfoResponse) { info.MaxConcurrentSigns = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			info := cloneInfoResponse(valid)
			test.mutate(&info)
			if err := ValidateGetInfoResponse(info); err == nil {
				t.Fatal("invalid info was accepted")
			}
		})
	}

	key := helperKey()
	if err := ValidateKey(key); err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	key.Binding.SignatureEncoding = "different"
	if err := ValidateKey(key); err == nil {
		t.Fatal("binding with wrong signature encoding was accepted")
	}

	key = helperKey()
	key.Binding.KeyID = string([]byte{0xff})
	if err := ValidateKey(key); err == nil {
		t.Fatal("binding with invalid UTF-8 key_id was accepted")
	}
}

func TestKeyReferenceValidationRejectsAmbiguityAndInlineSecrets(t *testing.T) {
	key := helperKey()
	key.Reference.PKCS11 = &PKCS11KeyReference{URI: "pkcs11:object=key;type=private"}
	if err := ValidateKey(key); err == nil {
		t.Fatal("multiple provider references were accepted")
	}

	key = helperKey()
	key.Binding.ProviderKind = ProviderPKCS11
	key.Reference = KeyReference{PKCS11: &PKCS11KeyReference{
		URI: "pkcs11:object=key;pin-value=1234;type=private",
	}}
	if err := ValidateKey(key); err == nil {
		t.Fatal("inline PKCS#11 PIN was accepted")
	}
	for _, uri := range []string{
		"pkcs11:object=key;pin%2dvalue=1234;type=private",
		"pkcs11:object=key;%70in-value=1234;type=private",
	} {
		key.Reference.PKCS11.URI = uri
		if err := ValidateKey(key); err == nil {
			t.Fatalf("encoded PKCS#11 attribute name was accepted: %q", uri)
		}
	}

	key = helperKey()
	key.Reference.Remote.Endpoint = "https://" + string(bytes.Repeat([]byte{'a'}, maxReferenceBytes)) + ".example"
	if err := ValidateKey(key); err == nil {
		t.Fatal("oversized remote endpoint was accepted")
	}
}

func TestResponseEncodingValidation(t *testing.T) {
	binding := helperKey().Binding
	if err := validatePublicKey(binding, bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatalf("valid Ed25519 public key rejected: %v", err)
	}
	if err := validatePublicKey(binding, bytes.Repeat([]byte{1}, 31)); err == nil {
		t.Fatal("short Ed25519 public key was accepted")
	}
	if err := validateSignature(binding, bytes.Repeat([]byte{1}, 64)); err != nil {
		t.Fatalf("valid-sized Ed25519 signature rejected: %v", err)
	}
	if err := validateSignature(binding, bytes.Repeat([]byte{1}, 63)); err == nil {
		t.Fatal("short Ed25519 signature was accepted")
	}
}

func TestFISCOBCOSStandardSignerProfileIsExact(t *testing.T) {
	binding := Binding{
		ProtocolVersion:   ProtocolVersion,
		PluginID:          "bcos-signer",
		ProviderKind:      ProviderRemote,
		CryptoSuite:       SuiteFISCOBCOSStandard,
		Algorithm:         AlgorithmSecp256k1,
		PublicKeyEncoding: Secp256k1PublicKeyEncoding,
		SignatureEncoding: Secp256k1SignatureEncoding,
		KeyID:             "publisher",
	}
	if err := ValidateBinding(binding); err != nil {
		t.Fatalf("valid FISCO BCOS binding rejected: %v", err)
	}
	publicKey := append([]byte{0x04}, bytes.Repeat([]byte{0x11}, 64)...)
	if err := validatePublicKey(binding, publicKey); err != nil {
		t.Fatalf("valid secp256k1 public key rejected: %v", err)
	}
	signature := bytes.Repeat([]byte{0x22}, 65)
	signature[64] = 1
	if err := validateSignature(binding, signature); err != nil {
		t.Fatalf("valid recoverable signature rejected: %v", err)
	}
	signature[64] = 2
	if err := validateSignature(binding, signature); err == nil {
		t.Fatal("out-of-range recovery id was accepted")
	}
}
