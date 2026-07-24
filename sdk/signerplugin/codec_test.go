package signerplugin

import (
	"bytes"
	"testing"
)

func TestCodecRequiresCanonicalCBOR(t *testing.T) {
	request := HealthRequest{ProtocolVersion: ProtocolVersion, PluginID: "test-signer"}
	canonical, err := Codec().Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded HealthRequest
	if err := Codec().Unmarshal(canonical, &decoded); err != nil {
		t.Fatalf("canonical message rejected: %v", err)
	}

	// Canonical CBOR orders these text keys by encoded length.  Construct the
	// same map in the opposite order to prove decode-and-reencode enforcement.
	protocolKey, _ := encMode.Marshal("protocol_version")
	protocolValue, _ := encMode.Marshal(ProtocolVersion)
	pluginKey, _ := encMode.Marshal("plugin_id")
	pluginValue, _ := encMode.Marshal("test-signer")
	nonCanonical := []byte{0xa2}
	nonCanonical = append(nonCanonical, protocolKey...)
	nonCanonical = append(nonCanonical, protocolValue...)
	nonCanonical = append(nonCanonical, pluginKey...)
	nonCanonical = append(nonCanonical, pluginValue...)
	if bytes.Equal(nonCanonical, canonical) {
		t.Fatal("test fixture unexpectedly canonical")
	}
	if err := Codec().Unmarshal(nonCanonical, &decoded); err == nil {
		t.Fatal("non-canonical CBOR was accepted")
	}
}

func TestCodecRejectsUnknownFieldsAndIndefiniteMaps(t *testing.T) {
	encoded, err := encMode.Marshal(map[string]any{
		"protocol_version": ProtocolVersion,
		"unexpected":       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var request GetInfoRequest
	if err := Codec().Unmarshal(encoded, &request); err == nil {
		t.Fatal("unknown field was accepted")
	}

	// A direct indefinite map must be rejected before struct decode.
	indefiniteMap := append([]byte{0xbf}, encodedMapPair(t, "protocol_version", ProtocolVersion)...)
	indefiniteMap = append(indefiniteMap, 0xff)
	if err := Codec().Unmarshal(indefiniteMap, &request); err == nil {
		t.Fatal("indefinite-length map was accepted")
	}
}

func TestCodecRejectsDuplicateKeysTagsTrailingDataAndInvalidUTF8(t *testing.T) {
	protocolPair := encodedMapPair(t, "protocol_version", ProtocolVersion)
	tests := map[string][]byte{
		"duplicate key": append(append([]byte{0xa2}, protocolPair...), protocolPair...),
		"tag":           append([]byte{0xc0}, mustEncode(t, GetInfoRequest{ProtocolVersion: ProtocolVersion})...),
		"trailing data": append(mustEncode(t, GetInfoRequest{ProtocolVersion: ProtocolVersion}), 0x00),
		"invalid UTF-8": append(append([]byte{0xa1}, mustEncode(t, "protocol_version")...), 0x61, 0xff),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			var request GetInfoRequest
			if err := Codec().Unmarshal(encoded, &request); err == nil {
				t.Fatal("malformed CBOR was accepted")
			}
		})
	}
}

func TestCodecMessageSizeBoundary(t *testing.T) {
	payload := bytes.Repeat([]byte{0x42}, MaxMessageBytes-5)
	encoded, err := Codec().Marshal(payload)
	if err != nil {
		t.Fatalf("exact-limit message rejected: %v", err)
	}
	if len(encoded) != MaxMessageBytes {
		t.Fatalf("encoded message size = %d, want %d", len(encoded), MaxMessageBytes)
	}
	var decoded []byte
	if err := Codec().Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("exact-limit message failed to decode: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatal("exact-limit message changed during round trip")
	}
	if _, err := Codec().Marshal(append(payload, 0x42)); err == nil {
		t.Fatal("oversized encoded message was accepted by Marshal")
	}
	if err := Codec().Unmarshal(make([]byte, MaxMessageBytes+1), &decoded); err == nil {
		t.Fatal("oversized encoded message was accepted by Unmarshal")
	}
}

func encodedMapPair(t *testing.T, key, value string) []byte {
	t.Helper()
	encodedKey, err := encMode.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	encodedValue, err := encMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return append(encodedKey, encodedValue...)
}

func mustEncode(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := encMode.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
