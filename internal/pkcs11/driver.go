package pkcs11

// backend hides the concrete PKCS#11 binding used by this repository.
// Today we use a single miekg-backed implementation, but tests can swap in a
// fake backend to exercise the package-owned surface directly.
type backend interface {
	open(path string) module
	newPSSParams(hashAlg, mgf, saltLength uint) []byte
}

type module interface {
	Initialize(...InitializeOption) error
	Finalize() error
	Destroy()
	OpenSession(slotID uint, flags uint) (SessionHandle, error)
	CloseSession(session SessionHandle) error
	Login(session SessionHandle, userType uint, pin string) error
	Logout(session SessionHandle) error
	GetSlotList(tokenPresent bool) ([]uint, error)
	GetSlotInfo(slotID uint) (SlotInfo, error)
	GetTokenInfo(slotID uint) (TokenInfo, error)
	GetAttributeValue(session SessionHandle, object ObjectHandle, attrs []*Attribute) ([]*Attribute, error)
	FindObjectsInit(session SessionHandle, template []*Attribute) error
	FindObjects(session SessionHandle, max int) ([]ObjectHandle, bool, error)
	FindObjectsFinal(session SessionHandle) error
	SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error
	Sign(session SessionHandle, data []byte) ([]byte, error)
}

var defaultBackend backend = miekgBackend{}
