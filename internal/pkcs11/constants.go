package pkcs11

import upstream "github.com/miekg/pkcs11"

const (
	CKA_CLASS            = upstream.CKA_CLASS
	CKA_CERTIFICATE_TYPE = upstream.CKA_CERTIFICATE_TYPE
	CKA_VALUE            = upstream.CKA_VALUE
	CKA_ID               = upstream.CKA_ID
	CKA_LABEL            = upstream.CKA_LABEL

	CKO_CERTIFICATE = upstream.CKO_CERTIFICATE
	CKO_PRIVATE_KEY = upstream.CKO_PRIVATE_KEY

	CKC_X_509 = upstream.CKC_X_509

	CKF_SERIAL_SESSION = upstream.CKF_SERIAL_SESSION
	CKF_LOGIN_REQUIRED = upstream.CKF_LOGIN_REQUIRED
	CKF_HW_SLOT        = upstream.CKF_HW_SLOT

	CKU_USER = upstream.CKU_USER

	CKR_USER_NOT_LOGGED_IN     = Error(upstream.CKR_USER_NOT_LOGGED_IN)
	CKR_USER_ALREADY_LOGGED_IN = Error(upstream.CKR_USER_ALREADY_LOGGED_IN)
	CKR_PIN_INCORRECT          = Error(upstream.CKR_PIN_INCORRECT)
	CKR_PIN_INVALID            = Error(upstream.CKR_PIN_INVALID)
	CKR_PIN_LEN_RANGE          = Error(upstream.CKR_PIN_LEN_RANGE)
	CKR_PIN_EXPIRED            = Error(upstream.CKR_PIN_EXPIRED)
	CKR_PIN_LOCKED             = Error(upstream.CKR_PIN_LOCKED)

	CKM_RSA_PKCS_PSS = upstream.CKM_RSA_PKCS_PSS
	CKM_RSA_PKCS     = upstream.CKM_RSA_PKCS
	CKM_ECDSA        = upstream.CKM_ECDSA
	CKM_SHA_1        = upstream.CKM_SHA_1
	CKM_SHA256       = upstream.CKM_SHA256
	CKM_SHA384       = upstream.CKM_SHA384
	CKM_SHA512       = upstream.CKM_SHA512

	CKG_MGF1_SHA1   = upstream.CKG_MGF1_SHA1
	CKG_MGF1_SHA256 = upstream.CKG_MGF1_SHA256
	CKG_MGF1_SHA384 = upstream.CKG_MGF1_SHA384
	CKG_MGF1_SHA512 = upstream.CKG_MGF1_SHA512
)
