//go:build pkcs11 && cgo

package pkcs11signer

import (
	"context"
	"errors"
	"math"
	"sync"

	"github.com/miekg/pkcs11"
)

// nativeBackend is the only place where TrustDB links a Cryptoki wrapper.
// It is built into the standalone signer sidecar, never the core server.
type nativeBackend struct {
	mu          sync.RWMutex
	module      *pkcs11.Ctx
	initialized bool
	closed      bool
}

// OpenNativeBackend loads and initializes one PKCS#11 module. Errors are
// intentionally sanitized before they can reach stderr or the host process.
func OpenNativeBackend(modulePath string) (Backend, error) {
	if modulePath == "" {
		return nil, newFault(faultInvalid)
	}
	module := pkcs11.New(modulePath)
	if module == nil {
		return nil, newFault(faultUnavailable)
	}
	backend := &nativeBackend{module: module}
	if err := module.Initialize(); err != nil {
		if !isPKCS11Error(err, pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
			module.Destroy()
			return nil, classifyNativeError(err)
		}
	} else {
		backend.initialized = true
	}
	return backend, nil
}

func (b *nativeBackend) Discover(ctx context.Context, selector TokenSelector) (Token, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.module == nil {
		return nil, newFault(faultUnavailable)
	}
	slots, err := b.module.GetSlotList(true)
	if err != nil {
		return nil, classifyNativeError(err)
	}
	var selected *nativeToken
	for _, slot := range slots {
		info, infoErr := b.module.GetTokenInfo(slot)
		if infoErr != nil {
			if isTransientNativeError(infoErr) {
				continue
			}
			return nil, classifyNativeError(infoErr)
		}
		identity := TokenIdentity{
			Label:        info.Label,
			Manufacturer: info.ManufacturerID,
			Model:        info.Model,
			Serial:       info.SerialNumber,
		}
		if !selector.matchesIdentity(identity) {
			continue
		}
		if selected != nil {
			return nil, newFault(faultPrecondition)
		}
		selected = &nativeToken{backend: b, slot: slot, identity: identity}
	}
	if selected == nil {
		return nil, newFault(faultUnavailable)
	}
	return selected, nil
}

func (b *nativeBackend) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	var closeErr error
	if b.module != nil {
		if b.initialized {
			if err := b.module.Finalize(); err != nil && !isPKCS11Error(err, pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED) {
				closeErr = newFault(faultInternal)
			}
		}
		b.module.Destroy()
		b.module = nil
	}
	return closeErr
}

type nativeToken struct {
	backend  *nativeBackend
	slot     uint
	identity TokenIdentity
}

func (t *nativeToken) Identity() TokenIdentity {
	if t == nil {
		return TokenIdentity{}
	}
	return t.identity
}

func (t *nativeToken) Mechanisms(ctx context.Context) ([]Mechanism, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.backend.mu.RLock()
	defer t.backend.mu.RUnlock()
	if t.backend.closed || t.backend.module == nil {
		return nil, newFault(faultUnavailable)
	}
	nativeMechanisms, err := t.backend.module.GetMechanismList(t.slot)
	if err != nil {
		return nil, classifyNativeError(err)
	}
	mechanisms := make([]Mechanism, 0, len(nativeMechanisms))
	for _, mechanism := range nativeMechanisms {
		if mechanism == nil {
			continue
		}
		info, infoErr := t.backend.module.GetMechanismInfo(t.slot, []*pkcs11.Mechanism{mechanism})
		if infoErr != nil {
			return nil, classifyNativeError(infoErr)
		}
		mechanisms = append(mechanisms, Mechanism{Type: mechanism.Mechanism, Flags: info.Flags})
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return mechanisms, nil
}

func (t *nativeToken) OpenSession(ctx context.Context) (Session, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	t.backend.mu.RLock()
	defer t.backend.mu.RUnlock()
	if t.backend.closed || t.backend.module == nil {
		return nil, newFault(faultUnavailable)
	}
	handle, err := t.backend.module.OpenSession(t.slot, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, classifyNativeError(err)
	}
	return &nativeSession{backend: t.backend, handle: handle}, nil
}

type nativeSession struct {
	backend *nativeBackend
	handle  pkcs11.SessionHandle

	closeOnce sync.Once
}

func (s *nativeSession) Login(ctx context.Context, pin []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	if s.backend.closed || s.backend.module == nil {
		return newFault(faultUnavailable)
	}
	// The miekg binding accepts a string and immediately copies it into the C
	// call. The caller clears the source bytes as soon as Login returns.
	err := s.backend.module.Login(s.handle, pkcs11.CKU_USER, string(pin))
	if err != nil && !isPKCS11Error(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		return classifyNativeError(err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (s *nativeSession) Lookup(ctx context.Context, selector ObjectSelector) (KeyMaterial, error) {
	if err := ctx.Err(); err != nil {
		return KeyMaterial{}, err
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	if s.backend.closed || s.backend.module == nil {
		return KeyMaterial{}, newFault(faultUnavailable)
	}
	privateTemplate := objectTemplate(pkcs11.CKO_PRIVATE_KEY, selector, false)
	privateHandle, found, err := s.findExactlyOne(privateTemplate)
	if err != nil {
		return KeyMaterial{}, err
	}
	if !found {
		return KeyMaterial{}, newFault(faultNotFound)
	}
	if err := s.validatePrivateKeyPolicy(privateHandle); err != nil {
		return KeyMaterial{}, err
	}
	publicTemplate := objectTemplate(pkcs11.CKO_PUBLIC_KEY, selector, true)
	publicHandle, publicFound, err := s.findExactlyOne(publicTemplate)
	if err != nil {
		return KeyMaterial{}, err
	}
	certificateTemplate := objectTemplate(pkcs11.CKO_CERTIFICATE, selector, true)
	certificateHandle, certificateFound, err := s.findExactlyOne(certificateTemplate)
	if err != nil {
		return KeyMaterial{}, err
	}
	material := KeyMaterial{Private: newObjectHandle(uint64(privateHandle))}
	if publicFound {
		material.ECPoint, err = s.optionalAttribute(publicHandle, pkcs11.CKA_EC_POINT)
		if err != nil {
			return KeyMaterial{}, err
		}
		material.PublicValue, err = s.optionalAttribute(publicHandle, pkcs11.CKA_VALUE)
		if err != nil {
			return KeyMaterial{}, err
		}
	}
	if certificateFound {
		material.CertificateDER, err = s.requiredAttribute(certificateHandle, pkcs11.CKA_VALUE)
		if err != nil {
			return KeyMaterial{}, err
		}
	}
	if len(material.ECPoint) == 0 && len(material.PublicValue) == 0 && len(material.CertificateDER) == 0 {
		return KeyMaterial{}, newFault(faultPrecondition)
	}
	if err := ctx.Err(); err != nil {
		return KeyMaterial{}, err
	}
	return material, nil
}

func (s *nativeSession) validatePrivateKeyPolicy(handle pkcs11.ObjectHandle) error {
	for _, requirement := range []struct {
		attribute uint
		want      bool
	}{
		{attribute: pkcs11.CKA_PRIVATE, want: true},
		{attribute: pkcs11.CKA_SENSITIVE, want: true},
		{attribute: pkcs11.CKA_EXTRACTABLE, want: false},
		{attribute: pkcs11.CKA_SIGN, want: true},
		{attribute: pkcs11.CKA_ALWAYS_SENSITIVE, want: true},
		{attribute: pkcs11.CKA_NEVER_EXTRACTABLE, want: true},
	} {
		value, err := s.requiredAttribute(handle, requirement.attribute)
		if err != nil {
			return err
		}
		if len(value) != 1 || (value[0] != 0) != requirement.want {
			return newFault(faultPrecondition)
		}
	}
	return nil
}

func (s *nativeSession) Sign(ctx context.Context, handle ObjectHandle, profile Profile, message []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if handle.value == 0 || handle.value > uint64(math.MaxUint) {
		return nil, newFault(faultInvalid)
	}
	s.backend.mu.RLock()
	defer s.backend.mu.RUnlock()
	if s.backend.closed || s.backend.module == nil {
		return nil, newFault(faultUnavailable)
	}
	mechanism := pkcs11.NewMechanism(profile.Mechanism, append([]byte(nil), profile.Parameter...))
	if err := s.backend.module.SignInit(s.handle, []*pkcs11.Mechanism{mechanism}, pkcs11.ObjectHandle(handle.value)); err != nil {
		return nil, classifyNativeError(err)
	}
	signature, err := s.backend.module.Sign(s.handle, message)
	if err != nil {
		return nil, classifyNativeError(err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]byte(nil), signature...), nil
}

func (s *nativeSession) Close() error {
	if s == nil || s.backend == nil {
		return nil
	}
	var closeErr error
	s.closeOnce.Do(func() {
		s.backend.mu.RLock()
		defer s.backend.mu.RUnlock()
		if s.backend.closed || s.backend.module == nil {
			return
		}
		if err := s.backend.module.CloseSession(s.handle); err != nil &&
			!isPKCS11Error(err, pkcs11.CKR_SESSION_CLOSED) &&
			!isPKCS11Error(err, pkcs11.CKR_SESSION_HANDLE_INVALID) {
			closeErr = newFault(faultInternal)
		}
	})
	return closeErr
}

func (s *nativeSession) findExactlyOne(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, bool, error) {
	if err := s.backend.module.FindObjectsInit(s.handle, template); err != nil {
		return 0, false, classifyNativeError(err)
	}
	objects, more, findErr := s.backend.module.FindObjects(s.handle, 2)
	finalErr := s.backend.module.FindObjectsFinal(s.handle)
	if findErr != nil {
		return 0, false, classifyNativeError(findErr)
	}
	if finalErr != nil {
		return 0, false, classifyNativeError(finalErr)
	}
	if more || len(objects) > 1 {
		return 0, false, newFault(faultPrecondition)
	}
	if len(objects) == 0 {
		return 0, false, nil
	}
	return objects[0], true, nil
}

func (s *nativeSession) optionalAttribute(handle pkcs11.ObjectHandle, attributeType uint) ([]byte, error) {
	value, err := s.rawAttribute(handle, attributeType)
	if err != nil {
		if isPKCS11Error(err, pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) ||
			isPKCS11Error(err, pkcs11.CKR_ATTRIBUTE_SENSITIVE) {
			return nil, nil
		}
		return nil, classifyNativeError(err)
	}
	if len(value) == 0 {
		return nil, nil
	}
	return value, nil
}

func (s *nativeSession) requiredAttribute(handle pkcs11.ObjectHandle, attributeType uint) ([]byte, error) {
	value, err := s.rawAttribute(handle, attributeType)
	if err != nil {
		return nil, classifyNativeError(err)
	}
	if len(value) == 0 {
		return nil, newFault(faultPrecondition)
	}
	return value, nil
}

func (s *nativeSession) rawAttribute(handle pkcs11.ObjectHandle, attributeType uint) ([]byte, error) {
	attributes, err := s.backend.module.GetAttributeValue(
		s.handle,
		handle,
		[]*pkcs11.Attribute{pkcs11.NewAttribute(attributeType, nil)},
	)
	if err != nil {
		return nil, err
	}
	if len(attributes) != 1 || attributes[0] == nil {
		return nil, nil
	}
	return append([]byte(nil), attributes[0].Value...), nil
}

func objectTemplate(class uint, selector ObjectSelector, relatedPublicObject bool) []*pkcs11.Attribute {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	// CKA_ID is the relationship key for private/public/certificate objects.
	// When it is present, a certificate is not required to reuse the private
	// object's label. The private-object search still binds every URI field.
	if len(selector.ID) != 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, append([]byte(nil), selector.ID...)))
	}
	if selector.Label != "" && (!relatedPublicObject || len(selector.ID) == 0) {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, selector.Label))
	}
	return template
}

func classifyNativeError(err error) error {
	if err == nil {
		return nil
	}
	var native pkcs11.Error
	if !errors.As(err, &native) {
		return newFault(faultInternal)
	}
	switch uint(native) {
	case pkcs11.CKR_ARGUMENTS_BAD, pkcs11.CKR_DATA_INVALID, pkcs11.CKR_DATA_LEN_RANGE,
		pkcs11.CKR_TEMPLATE_INCOMPLETE, pkcs11.CKR_TEMPLATE_INCONSISTENT,
		pkcs11.CKR_ATTRIBUTE_VALUE_INVALID:
		return newFault(faultInvalid)
	case pkcs11.CKR_KEY_HANDLE_INVALID, pkcs11.CKR_OBJECT_HANDLE_INVALID, pkcs11.CKR_KEY_CHANGED,
		pkcs11.CKR_ATTRIBUTE_TYPE_INVALID, pkcs11.CKR_ATTRIBUTE_SENSITIVE:
		return newFault(faultPrecondition)
	case pkcs11.CKR_PIN_INCORRECT, pkcs11.CKR_PIN_INVALID, pkcs11.CKR_PIN_LEN_RANGE,
		pkcs11.CKR_PIN_EXPIRED, pkcs11.CKR_PIN_LOCKED, pkcs11.CKR_USER_NOT_LOGGED_IN,
		pkcs11.CKR_USER_PIN_NOT_INITIALIZED, pkcs11.CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
		pkcs11.CKR_USER_TOO_MANY_TYPES:
		return newFault(faultAuthentication)
	case pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED, pkcs11.CKR_ACTION_PROHIBITED,
		pkcs11.CKR_SESSION_READ_ONLY:
		return newFault(faultPermission)
	case pkcs11.CKR_MECHANISM_INVALID, pkcs11.CKR_MECHANISM_PARAM_INVALID,
		pkcs11.CKR_FUNCTION_NOT_SUPPORTED, pkcs11.CKR_KEY_TYPE_INCONSISTENT,
		pkcs11.CKR_SESSION_PARALLEL_NOT_SUPPORTED:
		return newFault(faultUnsupported)
	case pkcs11.CKR_SESSION_COUNT, pkcs11.CKR_DEVICE_MEMORY, pkcs11.CKR_HOST_MEMORY,
		pkcs11.CKR_FUNCTION_REJECTED:
		return newFault(faultBusy)
	case pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_TOKEN_NOT_RECOGNIZED,
		pkcs11.CKR_SESSION_CLOSED, pkcs11.CKR_SESSION_HANDLE_INVALID, pkcs11.CKR_DEVICE_ERROR,
		pkcs11.CKR_CRYPTOKI_NOT_INITIALIZED, pkcs11.CKR_SLOT_ID_INVALID,
		pkcs11.CKR_FUNCTION_CANCELED:
		return newFault(faultUnavailable)
	default:
		return newFault(faultInternal)
	}
}

func isTransientNativeError(err error) bool {
	var native pkcs11.Error
	if !errors.As(err, &native) {
		return false
	}
	switch uint(native) {
	case pkcs11.CKR_DEVICE_REMOVED, pkcs11.CKR_TOKEN_NOT_PRESENT, pkcs11.CKR_TOKEN_NOT_RECOGNIZED,
		pkcs11.CKR_DEVICE_ERROR:
		return true
	default:
		return false
	}
}

func isPKCS11Error(err error, code uint) bool {
	var native pkcs11.Error
	return errors.As(err, &native) && uint(native) == code
}
