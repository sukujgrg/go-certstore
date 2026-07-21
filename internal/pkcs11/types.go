package pkcs11

import (
	"bytes"
	"unsafe"

	upstream "github.com/miekg/pkcs11"
)

// Context wraps the repository's PKCS#11 module implementation.
//
// A zero-value or nil Context is uninitialized; methods return an error instead
// of panicking, except Destroy which is a no-op in that state.
type Context struct {
	mod module
}

// InitializeOption configures PKCS#11 module initialization.
type InitializeOption struct {
	reserved unsafe.Pointer
}

// Attribute stores the encoded PKCS#11 value bytes for a single attribute.
type Attribute struct {
	// Type identifies the PKCS#11 attribute.
	Type uint
	// Value contains the encoded PKCS#11 attribute value.
	Value []byte
}

// Mechanism describes a PKCS#11 mechanism and its encoded parameter.
type Mechanism struct {
	// Mechanism identifies the PKCS#11 mechanism.
	Mechanism uint
	// Parameter contains the encoded mechanism parameter, or nil when the
	// mechanism has no parameter.
	Parameter interface{}
}

// ObjectHandle identifies an object within a PKCS#11 session.
type ObjectHandle uint

// SessionHandle identifies an open PKCS#11 session.
type SessionHandle uint

// SlotInfo contains the slot metadata used by the parent certstore package.
type SlotInfo struct {
	// Flags contains the PKCS#11 slot flags.
	Flags uint
}

// TokenInfo contains the token metadata used by the parent certstore package.
type TokenInfo struct {
	// Label is the token label as returned by the PKCS#11 module.
	Label string
	// SerialNumber is the token serial number as returned by the PKCS#11 module.
	SerialNumber string
	// Flags contains the PKCS#11 token flags.
	Flags uint
}

// Error preserves the upstream PKCS#11 error code while exposing it as a
// package-owned type.
type Error uint

// Error returns the message for the underlying PKCS#11 error code.
func (e Error) Error() string {
	return upstream.Error(e).Error()
}

// InitializeWithReserved returns an initialization option containing the
// PKCS#11 pReserved value.
func InitializeWithReserved(reserved unsafe.Pointer) InitializeOption {
	return InitializeOption{reserved: reserved}
}

// NewAttribute mirrors miekg/pkcs11's attribute encoding while keeping the
// resulting bytes owned by this package.
func NewAttribute(typ uint, value interface{}) *Attribute {
	attr := upstream.NewAttribute(typ, value)
	if attr == nil {
		return nil
	}
	return &Attribute{
		Type:  attr.Type,
		Value: bytes.Clone(attr.Value),
	}
}

// NewMechanism constructs the subset of mechanism parameters this repository
// currently needs: nil and raw []byte parameter blobs. It copies []byte
// parameters into package-owned storage so invalid or out-of-scope inputs fail
// here instead of later during upstream mechanism serialization.
func NewMechanism(mechanism uint, parameter interface{}) *Mechanism {
	return &Mechanism{
		Mechanism: mechanism,
		Parameter: cloneMechanismParameter(parameter),
	}
}

func cloneMechanismParameter(parameter interface{}) interface{} {
	switch value := parameter.(type) {
	case nil:
		return nil
	case []byte:
		return bytes.Clone(value)
	default:
		panic("parameter must be nil or []byte")
	}
}
