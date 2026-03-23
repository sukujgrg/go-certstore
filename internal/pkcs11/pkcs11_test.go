package pkcs11

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	upstream "github.com/miekg/pkcs11"
)

type fakeBackend struct {
	path string
	mod  module
}

func (b *fakeBackend) open(path string) module {
	b.path = path
	return b.mod
}

func (b *fakeBackend) newPSSParams(hashAlg, mgf, saltLength uint) []byte {
	return []byte{byte(hashAlg), byte(mgf), byte(saltLength)}
}

type fakeModule struct {
	slotList []uint
}

type typedNilBackend struct{}

func (*typedNilBackend) open(string) module { return nil }

func (*typedNilBackend) newPSSParams(uint, uint, uint) []byte { return nil }

type typedNilModule struct{}

func (*typedNilModule) Initialize(...InitializeOption) error { return nil }
func (*typedNilModule) Finalize() error                      { return nil }
func (*typedNilModule) Destroy()                             {}
func (*typedNilModule) OpenSession(uint, uint) (SessionHandle, error) {
	return 0, nil
}
func (*typedNilModule) CloseSession(SessionHandle) error { return nil }
func (*typedNilModule) Login(SessionHandle, uint, string) error {
	return nil
}
func (*typedNilModule) Logout(SessionHandle) error { return nil }
func (*typedNilModule) GetSlotList(bool) ([]uint, error) {
	return nil, nil
}
func (*typedNilModule) GetSlotInfo(uint) (SlotInfo, error) {
	return SlotInfo{}, nil
}
func (*typedNilModule) GetTokenInfo(uint) (TokenInfo, error) {
	return TokenInfo{}, nil
}
func (*typedNilModule) GetAttributeValue(SessionHandle, ObjectHandle, []*Attribute) ([]*Attribute, error) {
	return nil, nil
}
func (*typedNilModule) FindObjectsInit(SessionHandle, []*Attribute) error { return nil }
func (*typedNilModule) FindObjects(SessionHandle, int) ([]ObjectHandle, bool, error) {
	return nil, false, nil
}
func (*typedNilModule) FindObjectsFinal(SessionHandle) error { return nil }
func (*typedNilModule) SignInit(SessionHandle, []*Mechanism, ObjectHandle) error {
	return nil
}
func (*typedNilModule) Sign(SessionHandle, []byte) ([]byte, error) { return nil, nil }

func (m *fakeModule) Initialize(...InitializeOption) error { return nil }
func (m *fakeModule) Finalize() error                      { return nil }
func (m *fakeModule) Destroy()                             {}
func (m *fakeModule) OpenSession(uint, uint) (SessionHandle, error) {
	return 0, nil
}
func (m *fakeModule) CloseSession(SessionHandle) error { return nil }
func (m *fakeModule) Login(SessionHandle, uint, string) error {
	return nil
}
func (m *fakeModule) Logout(SessionHandle) error { return nil }
func (m *fakeModule) GetSlotList(bool) ([]uint, error) {
	return m.slotList, nil
}
func (m *fakeModule) GetSlotInfo(uint) (SlotInfo, error) {
	return SlotInfo{}, nil
}
func (m *fakeModule) GetTokenInfo(uint) (TokenInfo, error) {
	return TokenInfo{}, nil
}
func (m *fakeModule) GetAttributeValue(SessionHandle, ObjectHandle, []*Attribute) ([]*Attribute, error) {
	return nil, nil
}
func (m *fakeModule) FindObjectsInit(SessionHandle, []*Attribute) error { return nil }
func (m *fakeModule) FindObjects(SessionHandle, int) ([]ObjectHandle, bool, error) {
	return nil, false, nil
}
func (m *fakeModule) FindObjectsFinal(SessionHandle) error { return nil }
func (m *fakeModule) SignInit(SessionHandle, []*Mechanism, ObjectHandle) error {
	return nil
}
func (m *fakeModule) Sign(SessionHandle, []byte) ([]byte, error) { return nil, nil }

func TestNewWithBackendUsesConfiguredBackend(t *testing.T) {
	b := &fakeBackend{
		mod: &fakeModule{slotList: []uint{3, 9}},
	}

	ctx := newWithBackend("/tmp/test-module.so", b)
	if ctx == nil {
		t.Fatal("newWithBackend returned nil")
	}
	if b.path != "/tmp/test-module.so" {
		t.Fatalf("open path = %q", b.path)
	}

	slots, err := ctx.GetSlotList(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(slots) != 2 || slots[0] != 3 || slots[1] != 9 {
		t.Fatalf("GetSlotList() = %v", slots)
	}
}

func TestNewWithBackendRejectsNilBackend(t *testing.T) {
	if ctx := newWithBackend("/tmp/test-module.so", nil); ctx != nil {
		t.Fatal("newWithBackend(nil) returned context")
	}
}

func TestNewWithBackendRejectsTypedNilBackend(t *testing.T) {
	var b *typedNilBackend
	if ctx := newWithBackend("/tmp/test-module.so", b); ctx != nil {
		t.Fatal("newWithBackend(typed nil backend) returned context")
	}
}

func TestZeroValueContextReturnsError(t *testing.T) {
	var ctx Context

	if err := ctx.Initialize(); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("Initialize() error = %v", err)
	}
	if _, err := ctx.GetSlotList(true); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("GetSlotList() error = %v", err)
	}
	if _, err := ctx.Sign(0, nil); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("Sign() error = %v", err)
	}
}

func TestTypedNilModuleReturnsError(t *testing.T) {
	var mod *typedNilModule
	ctx := &Context{mod: mod}

	if err := ctx.Initialize(); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("Initialize() error = %v", err)
	}
	if _, err := ctx.GetSlotList(true); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("GetSlotList() error = %v", err)
	}
}

func TestNilContextReturnsError(t *testing.T) {
	var ctx *Context

	if _, err := ctx.OpenSession(1, CKF_SERIAL_SESSION); !errors.Is(err, errUninitializedContext) {
		t.Fatalf("OpenSession() error = %v", err)
	}

	// Destroy should remain a no-op for nil contexts.
	ctx.Destroy()
}

func TestWrapErrorConvertsUpstreamPKCS11Errors(t *testing.T) {
	err := wrapError(upstream.Error(upstream.CKR_PIN_LOCKED))
	var pkErr Error
	if !errors.As(err, &pkErr) {
		t.Fatalf("errors.As(%T, *Error) = false", err)
	}
	if pkErr != CKR_PIN_LOCKED {
		t.Fatalf("pk error = %v", pkErr)
	}
	if !strings.Contains(pkErr.Error(), "CKR_PIN_LOCKED") {
		t.Fatalf("error string = %q", pkErr.Error())
	}
}

func TestWrapErrorPassesThroughNonPKCS11Errors(t *testing.T) {
	err := errors.New("boom")
	if got := wrapError(err); got != err {
		t.Fatalf("wrapError(non-pkcs11) changed error: %v", got)
	}
}

func TestInitializeWithReservedStoresPointer(t *testing.T) {
	ptr := unsafe.Pointer(new(byte))
	opt := InitializeWithReserved(ptr)
	if opt.reserved != ptr {
		t.Fatal("InitializeWithReserved did not preserve reserved pointer")
	}
}

func TestNewPSSParamsUsesDefaultBackend(t *testing.T) {
	orig := defaultBackend
	t.Cleanup(func() {
		defaultBackend = orig
	})

	defaultBackend = &fakeBackend{}
	got := NewPSSParams(1, 2, 3)
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("NewPSSParams() = %v", got)
	}
}

func TestNewPSSParamsWithNilBackendReturnsNil(t *testing.T) {
	orig := defaultBackend
	t.Cleanup(func() {
		defaultBackend = orig
	})

	defaultBackend = nil
	if got := NewPSSParams(1, 2, 3); got != nil {
		t.Fatalf("NewPSSParams() = %v, want nil", got)
	}
}

func TestNewPSSParamsWithTypedNilBackendReturnsNil(t *testing.T) {
	orig := defaultBackend
	t.Cleanup(func() {
		defaultBackend = orig
	})

	var b *typedNilBackend
	defaultBackend = b
	if got := NewPSSParams(1, 2, 3); got != nil {
		t.Fatalf("NewPSSParams() = %v, want nil", got)
	}
}

func TestNewAttributePopulatesEncodedValue(t *testing.T) {
	attr := NewAttribute(CKA_LABEL, "key-label")
	if attr == nil {
		t.Fatal("NewAttribute() returned nil")
	}
	if attr.Type != CKA_LABEL {
		t.Fatalf("Type = %d", attr.Type)
	}
	if string(attr.Value) != "key-label" {
		t.Fatalf("Value = %q", attr.Value)
	}
}

func TestNewAttributeClonesByteInput(t *testing.T) {
	src := []byte{0x01, 0x02}
	attr := NewAttribute(CKA_ID, src)
	src[0] = 0xFF
	if attr.Value[0] != 0x01 {
		t.Fatalf("attribute value aliased source slice: %v", attr.Value)
	}
}

func TestNewMechanismClonesByteParameter(t *testing.T) {
	src := []byte{0x01, 0x02}
	mech := NewMechanism(CKM_RSA_PKCS_PSS, src)
	src[0] = 0xFF

	got, ok := mech.Parameter.([]byte)
	if !ok {
		t.Fatalf("Parameter type = %T", mech.Parameter)
	}
	if got[0] != 0x01 {
		t.Fatalf("mechanism parameter aliased source slice: %v", got)
	}
}

func TestNewMechanismRejectsUnsupportedParameterType(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewMechanism() did not panic for unsupported parameter type")
		}
	}()

	NewMechanism(CKM_RSA_PKCS_PSS, struct{}{})
}

func TestNewMechanismRejectsTypedNilPointerParameter(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewMechanism() did not panic for typed nil pointer parameter")
		}
	}()

	var params *upstream.OAEPParams
	NewMechanism(CKM_RSA_PKCS_PSS, params)
}

func TestToUpstreamAttributesPreservesRawValues(t *testing.T) {
	attrs := []*Attribute{
		NewAttribute(CKA_CLASS, CKO_PRIVATE_KEY),
		NewAttribute(CKA_LABEL, "key-label"),
		NewAttribute(CKA_ID, []byte{0x01, 0x02}),
		nil,
	}

	got := toUpstreamAttributes(attrs)
	if len(got) != len(attrs) {
		t.Fatalf("toUpstreamAttributes() len = %d", len(got))
	}
	if got[0] == nil || got[0].Type != CKA_CLASS {
		t.Fatalf("class attribute = %#v", got[0])
	}
	if got[1] == nil || string(got[1].Value) != "key-label" {
		t.Fatalf("label attribute value = %q", got[1].Value)
	}
	if got[2] == nil || len(got[2].Value) != 2 || got[2].Value[0] != 0x01 || got[2].Value[1] != 0x02 {
		t.Fatalf("id attribute value = %v", got[2].Value)
	}
	if got[3] != nil {
		t.Fatalf("nil attribute was not preserved: %#v", got[3])
	}
}

func TestToUpstreamAttributesUsesCurrentValueBytes(t *testing.T) {
	attr := NewAttribute(CKA_LABEL, "old")
	attr.Value = []byte("new")

	got := toUpstreamAttributes([]*Attribute{attr})
	if len(got) != 1 || got[0] == nil {
		t.Fatalf("toUpstreamAttributes() = %#v", got)
	}
	if string(got[0].Value) != "new" {
		t.Fatalf("encoded value = %q", got[0].Value)
	}

	got[0].Value[0] = 'x'
	if string(attr.Value) != "new" {
		t.Fatalf("attribute value was mutated through upstream conversion: %q", attr.Value)
	}
}

func TestFromUpstreamAttributesCopiesVisibleFields(t *testing.T) {
	src := []*upstream.Attribute{
		{Type: CKA_LABEL, Value: []byte("label")},
		nil,
	}

	got := fromUpstreamAttributes(src)
	if len(got) != len(src) {
		t.Fatalf("fromUpstreamAttributes() len = %d", len(got))
	}
	if got[0] == nil || got[0].Type != CKA_LABEL || string(got[0].Value) != "label" {
		t.Fatalf("attribute = %#v", got[0])
	}
	if got[1] != nil {
		t.Fatalf("nil attribute was not preserved: %#v", got[1])
	}

	src[0].Value[0] = 'x'
	if string(got[0].Value) != "label" {
		t.Fatalf("attribute value aliased source slice: %q", got[0].Value)
	}
}

func TestToUpstreamMechanismsPreservesParameters(t *testing.T) {
	mechs := []*Mechanism{
		NewMechanism(CKM_RSA_PKCS, nil),
		NewMechanism(CKM_RSA_PKCS_PSS, []byte{1, 2, 3}),
		nil,
	}

	got := toUpstreamMechanisms(mechs)
	if len(got) != len(mechs) {
		t.Fatalf("toUpstreamMechanisms() len = %d", len(got))
	}
	if got[0] == nil || got[0].Mechanism != CKM_RSA_PKCS {
		t.Fatalf("mechanism[0] = %#v", got[0])
	}
	if got[1] == nil || got[1].Mechanism != CKM_RSA_PKCS_PSS {
		t.Fatalf("mechanism[1] = %#v", got[1])
	}
	if got[2] != nil {
		t.Fatalf("nil mechanism was not preserved: %#v", got[2])
	}

	got[1].Parameter[0] = 0xFF
	param, ok := mechs[1].Parameter.([]byte)
	if !ok {
		t.Fatalf("Parameter type = %T", mechs[1].Parameter)
	}
	if param[0] != 1 {
		t.Fatalf("mechanism parameter was mutated through upstream conversion: %v", param)
	}
}
