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

type InitializeOption struct {
	reserved unsafe.Pointer
}

// Attribute stores the encoded PKCS#11 value bytes for a single attribute.
type Attribute struct {
	Type  uint
	Value []byte
}

type Mechanism struct {
	Mechanism uint
	Parameter interface{}
}

type ObjectHandle uint

type SessionHandle uint

type SlotInfo struct {
	Flags uint
}

type TokenInfo struct {
	Label        string
	SerialNumber string
	Flags        uint
}

// Error preserves the upstream PKCS#11 error code while exposing it as a
// package-owned type.
type Error uint

func (e Error) Error() string {
	return upstream.Error(e).Error()
}

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

// NewMechanism mirrors miekg/pkcs11's accepted mechanism parameter types while
// copying []byte parameters into package-owned storage. Supported pointer
// parameter types must be non-nil so invalid inputs fail here instead of later
// during upstream mechanism serialization.
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
	case *upstream.GCMParams:
		if value == nil {
			panic("parameter must not be a nil *GCMParams")
		}
		return parameter
	case *upstream.OAEPParams:
		if value == nil {
			panic("parameter must not be a nil *OAEPParams")
		}
		return parameter
	case *upstream.ECDH1DeriveParams:
		if value == nil {
			panic("parameter must not be a nil *ECDH1DeriveParams")
		}
		return parameter
	case *upstream.RSAAESKeyWrapParams:
		if value == nil {
			panic("parameter must not be a nil *RSAAESKeyWrapParams")
		}
		return parameter
	default:
		panic("parameter must be one of type: []byte, *GCMParams, *OAEPParams, *ECDH1DeriveParams," +
			" *RSAAESKeyWrapParams")
	}
}
