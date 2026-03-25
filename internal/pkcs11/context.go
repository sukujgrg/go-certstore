package pkcs11

import (
	"errors"
	"reflect"
)

var errUninitializedContext = errors.New("pkcs11: context is nil or uninitialized")

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

func NewPSSParams(hashAlg, mgf, saltLength uint) []byte {
	if isNilValue(defaultBackend) {
		return nil
	}
	return defaultBackend.newPSSParams(hashAlg, mgf, saltLength)
}

func (c *Context) Initialize(opts ...InitializeOption) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Initialize(opts...)
}

func (c *Context) Finalize() error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Finalize()
}

func (c *Context) Destroy() {
	mod, err := c.module()
	if err != nil {
		return
	}
	mod.Destroy()
}

func (c *Context) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	mod, err := c.module()
	if err != nil {
		return 0, err
	}
	return mod.OpenSession(slotID, flags)
}

func (c *Context) CloseSession(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.CloseSession(session)
}

func (c *Context) Login(session SessionHandle, userType uint, pin string) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Login(session, userType, pin)
}

func (c *Context) Logout(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.Logout(session)
}

func (c *Context) GetSlotList(tokenPresent bool) ([]uint, error) {
	mod, err := c.module()
	if err != nil {
		return nil, err
	}
	return mod.GetSlotList(tokenPresent)
}

func (c *Context) GetSlotInfo(slotID uint) (SlotInfo, error) {
	mod, err := c.module()
	if err != nil {
		return SlotInfo{}, err
	}
	return mod.GetSlotInfo(slotID)
}

func (c *Context) GetTokenInfo(slotID uint) (TokenInfo, error) {
	mod, err := c.module()
	if err != nil {
		return TokenInfo{}, err
	}
	return mod.GetTokenInfo(slotID)
}

func (c *Context) GetAttributeValue(session SessionHandle, object ObjectHandle, attrs []*Attribute) ([]*Attribute, error) {
	mod, err := c.module()
	if err != nil {
		return nil, err
	}
	return mod.GetAttributeValue(session, object, attrs)
}

func (c *Context) FindObjectsInit(session SessionHandle, template []*Attribute) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.FindObjectsInit(session, template)
}

func (c *Context) FindObjects(session SessionHandle, max int) ([]ObjectHandle, bool, error) {
	mod, err := c.module()
	if err != nil {
		return nil, false, err
	}
	return mod.FindObjects(session, max)
}

func (c *Context) FindObjectsFinal(session SessionHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.FindObjectsFinal(session)
}

func (c *Context) SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	mod, err := c.module()
	if err != nil {
		return err
	}
	return mod.SignInit(session, mechanisms, key)
}

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
