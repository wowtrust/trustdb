//go:build pkcs11 && cgo

package pkcs11signer

import (
	"errors"
	"testing"

	"github.com/miekg/pkcs11"
)

func TestClassifyNativeError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		code  uint
		class faultClass
	}{
		{name: "invalid", code: pkcs11.CKR_ARGUMENTS_BAD, class: faultInvalid},
		{name: "authentication", code: pkcs11.CKR_PIN_INCORRECT, class: faultAuthentication},
		{name: "permission", code: pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED, class: faultPermission},
		{name: "unsupported", code: pkcs11.CKR_MECHANISM_INVALID, class: faultUnsupported},
		{name: "busy", code: pkcs11.CKR_SESSION_COUNT, class: faultBusy},
		{name: "removed", code: pkcs11.CKR_DEVICE_REMOVED, class: faultUnavailable},
		{name: "session loss", code: pkcs11.CKR_SESSION_HANDLE_INVALID, class: faultUnavailable},
		{name: "identity", code: pkcs11.CKR_KEY_CHANGED, class: faultPrecondition},
		{name: "unknown vendor", code: pkcs11.CKR_VENDOR_DEFINED + 7, class: faultInternal},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := classifyNativeError(pkcs11.Error(test.code))
			var fault *Fault
			if !errors.As(err, &fault) || fault.class != test.class {
				t.Fatalf("classifyNativeError() = %v, want class %d", err, test.class)
			}
			if containsNativeDiagnostic(err.Error()) {
				t.Fatalf("classified error leaked native diagnostic: %q", err)
			}
		})
	}
}

func TestObjectTemplateUsesIDToRelateCertificate(t *testing.T) {
	t.Parallel()
	selector := ObjectSelector{Label: "private-label", ID: []byte{1, 2}}
	privateTemplate := objectTemplate(pkcs11.CKO_PRIVATE_KEY, selector, false)
	publicTemplate := objectTemplate(pkcs11.CKO_PUBLIC_KEY, selector, true)
	if len(privateTemplate) != 3 {
		t.Fatalf("private template attribute count = %d, want 3", len(privateTemplate))
	}
	if len(publicTemplate) != 2 {
		t.Fatalf("related public template attribute count = %d, want 2", len(publicTemplate))
	}
	if publicTemplate[1].Type != pkcs11.CKA_ID || string(publicTemplate[1].Value) != "\x01\x02" {
		t.Fatal("related public template did not use the exact CKA_ID")
	}
}

func containsNativeDiagnostic(value string) bool {
	for _, needle := range []string{"pkcs11:", "CKR_", "0x"} {
		if len(value) >= len(needle) {
			for i := 0; i+len(needle) <= len(value); i++ {
				if value[i:i+len(needle)] == needle {
					return true
				}
			}
		}
	}
	return false
}
