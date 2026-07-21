package pkcs11

import (
	"errors"
	"fmt"
	"reflect"
)

var errUninitializedContext = errors.New("pkcs11: context is nil or uninitialized")

// New returns an uninitialized PKCS#11 context for the module at path.
func New(path string) *Context {
	return newWithBackend(path, defaultBackend)
}

func newWithBackend(path string, b backend) *Context {
	if isNilValue(b) {
		return nil
	}
	mod := b.open(path)
	if isNilValue(mod) {
		return nil
	}
	return &Context{mod: mod}
}

// NewPSSParams encodes parameters for the CKM_RSA_PKCS_PSS mechanism.
func NewPSSParams(hashAlg, mgf, saltLength uint) []byte {
	if isNilValue(defaultBackend) {
		return nil
	}
	return defaultBackend.newPSSParams(hashAlg, mgf, saltLength)
}

// Initialize initializes the PKCS#11 module.
func (c *Context) Initialize(opts ...InitializeOption) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Initialize(opts...)
}

// Finalize finalizes the PKCS#11 module.
func (c *Context) Finalize() error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Finalize()
}

// Destroy releases the underlying PKCS#11 module wrapper.
func (c *Context) Destroy() {
	mod, err := c.module()
	if err != nil {
		return
	}
	mod.Destroy()
}

// OpenSession opens a session on slotID with the supplied PKCS#11 flags.
func (c *Context) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	mod, err := c.module()
	if err != nil {
		return 0, err
	}
	return mod.OpenSession(slotID, flags)
}

// CloseSession closes session.
func (c *Context) CloseSession(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.CloseSession(session)
}

// Login authenticates userType to session with pin.
func (c *Context) Login(session SessionHandle, userType uint, pin string) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Login(session, userType, pin)
}

// Logout ends the authenticated state of session.
func (c *Context) Logout(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Logout(session)
}

// GetSlotList returns slots, optionally limited to slots with a token present.
func (c *Context) GetSlotList(tokenPresent bool) ([]uint, error) {
	mod, err := c.module()
	if err != nil {
		return nil, err
	}
	return mod.GetSlotList(tokenPresent)
}

// GetSlotInfo returns metadata for slotID.
func (c *Context) GetSlotInfo(slotID uint) (SlotInfo, error) {
	mod, err := c.module()
	if err != nil {
		return SlotInfo{}, err
	}
	return mod.GetSlotInfo(slotID)
}

// GetTokenInfo returns token metadata for slotID.
func (c *Context) GetTokenInfo(slotID uint) (TokenInfo, error) {
	mod, err := c.module()
	if err != nil {
		return TokenInfo{}, err
	}
	return mod.GetTokenInfo(slotID)
}

// GetAttributeValue returns the requested attributes for object in session.
func (c *Context) GetAttributeValue(session SessionHandle, object ObjectHandle, attrs []*Attribute) ([]*Attribute, error) {
	mod, err := c.module()
	if err != nil {
		return nil, err
	}
	if err := validateAttributes(attrs); err != nil {
		return nil, err
	}
	return mod.GetAttributeValue(session, object, attrs)
}

// FindObjectsInit starts an object search in session using template.
func (c *Context) FindObjectsInit(session SessionHandle, template []*Attribute) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	if err := validateAttributes(template); err != nil {
		return err
	}
	return mod.FindObjectsInit(session, template)
}

// FindObjects returns up to max objects from the active search in session. The
// Boolean result reports whether the module may have more objects.
func (c *Context) FindObjects(session SessionHandle, max int) ([]ObjectHandle, bool, error) {
	mod, err := c.module()
	if err != nil {
		return nil, false, err
	}
	return mod.FindObjects(session, max)
}

// FindObjectsFinal ends the active object search in session.
func (c *Context) FindObjectsFinal(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.FindObjectsFinal(session)
}

// SignInit starts a signing operation in session with key. Exactly one
// mechanism is required.
func (c *Context) SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	if len(mechanisms) != 1 {
		return fmt.Errorf("pkcs11: SignInit requires exactly one mechanism, got %d", len(mechanisms))
	}
	if mechanisms[0] == nil {
		return errors.New("pkcs11: SignInit mechanism must not be nil")
	}
	return mod.SignInit(session, mechanisms, key)
}

func validateAttributes(attrs []*Attribute) error {
	for i, attr := range attrs {
		if attr == nil {
			return fmt.Errorf("pkcs11: attribute %d must not be nil", i)
		}
	}
	return nil
}

// Sign signs data with the active signing operation in session.
func (c *Context) Sign(session SessionHandle, data []byte) ([]byte, error) {
	mod, err := c.module()
	if err != nil {
		return nil, err
	}
	return mod.Sign(session, data)
}

func (c *Context) module() (module, error) {
	if c == nil || isNilValue(c.mod) {
		return nil, errUninitializedContext
	}
	return c.mod, nil
}

func isNilValue(v interface{}) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
