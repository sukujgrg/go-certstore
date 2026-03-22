package certstore

import "errors"

var (
	// ErrUnsupportedHash is returned when the requested hash algorithm is not
	// supported by the underlying platform signing implementation.
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")

	// ErrUnsupportedBackend is returned when the selected backend is not
	// supported on the current platform or not implemented yet.
	ErrUnsupportedBackend = errors.New("unsupported backend")

	// ErrIdentityNotFound is returned when no matching identity can be found.
	ErrIdentityNotFound = errors.New("identity not found")

	// ErrLoginRequired is returned when backend access requires an explicit
	// login step before the requested operation can proceed.
	ErrLoginRequired = errors.New("login required")

	// ErrCredentialRequired is returned when a backend requires credentials.
	ErrCredentialRequired = errors.New("credential required")

	// ErrIncorrectCredential is returned when provided credentials are rejected.
	ErrIncorrectCredential = errors.New("incorrect credential")

	// ErrMechanismUnsupported is returned when a backend cannot perform a
	// requested signing or key operation.
	ErrMechanismUnsupported = errors.New("mechanism unsupported")

	// ErrClosed is returned when an operation is attempted on a closed resource.
	ErrClosed = errors.New("closed")

	// ErrInvalidConfiguration is returned when the supplied backend or option
	// combination is incomplete or inconsistent.
	ErrInvalidConfiguration = errors.New("invalid configuration")
)
