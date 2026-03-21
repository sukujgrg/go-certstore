//go:build cgo

package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strings"
	"sync"

	"github.com/miekg/pkcs11"
)

func openPKCS11Store(cfg Options) (Store, error) {
	module, err := newPKCS11Module(cfg)
	if err != nil {
		return nil, err
	}
	return &pkcs11Store{module: module}, nil
}

type tokenModuleConfig struct {
	backend    Backend
	modulePath string
	prompt     func(PromptInfo) (string, error)
	initOpts   []pkcs11.InitializeOption
	cleanup    func()
	selectSlot func(*pkcs11.Ctx) (uint, pkcs11.SlotInfo, pkcs11.TokenInfo, error)
}

type pkcs11Store struct {
	module *pkcs11Module
	once   sync.Once
}

func (s *pkcs11Store) Identities() ([]Identity, error) {
	session, err := s.module.openSession()
	if err != nil {
		return nil, err
	}
	defer s.module.closeSession(session)

	certObjects, err := s.loadCertificateObjects(session)
	if err != nil {
		return nil, err
	}

	chainPool := make([]*x509.Certificate, 0, len(certObjects))
	for _, certObject := range certObjects {
		chainPool = append(chainPool, certObject.cert)
	}

	idents := make([]Identity, 0, len(certObjects))
	loggedIn := false
	for _, certObject := range certObjects {
		hasKey, err := s.module.hasPrivateKey(session, certObject.keyID, certObject.label)
		if err != nil && isPKCS11Error(err, pkcs11.CKR_USER_NOT_LOGGED_IN) {
			if !loggedIn {
				if err := s.module.login(session); err != nil {
					return nil, err
				}
				loggedIn = true
			}
			hasKey, err = s.module.hasPrivateKey(session, certObject.keyID, certObject.label)
		}
		if err != nil {
			return nil, err
		}
		if !hasKey && !loggedIn && s.module.tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0 {
			if err := s.module.login(session); err != nil {
				return nil, err
			}
			loggedIn = true
			hasKey, err = s.module.hasPrivateKey(session, certObject.keyID, certObject.label)
			if err != nil {
				return nil, err
			}
		}
		if !hasKey {
			continue
		}
		moduleRef, err := s.module.retain()
		if err != nil {
			return nil, err
		}
		idents = append(idents, &pkcs11Identity{
			module:    moduleRef,
			certDER:   cloneBytes(certObject.raw),
			keyID:     cloneBytes(certObject.keyID),
			label:     certObject.label,
			cert:      certObject.cert,
			chainPool: chainPool,
		})
	}
	return idents, nil
}

func (s *pkcs11Store) loadCertificateObjects(session pkcs11.SessionHandle) ([]pkcs11CertificateObject, error) {
	objects, err := findPKCS11Objects(s.module.ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
		pkcs11.NewAttribute(pkcs11.CKA_CERTIFICATE_TYPE, pkcs11.CKC_X_509),
	})
	if err != nil {
		return nil, err
	}

	certs := make([]pkcs11CertificateObject, 0, len(objects))
	for _, object := range objects {
		attrs, err := s.module.ctx.GetAttributeValue(session, object, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
			pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
		})
		if err != nil {
			continue
		}

		raw := attrs[0].Value
		if len(raw) == 0 {
			continue
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			continue
		}

		certs = append(certs, pkcs11CertificateObject{
			raw:   cloneBytes(raw),
			cert:  cert,
			keyID: cloneBytes(attrs[1].Value),
			label: strings.TrimSpace(string(attrs[2].Value)),
		})
	}
	return certs, nil
}

func (s *pkcs11Store) Close() {
	s.once.Do(func() {
		if s.module != nil {
			s.module.release()
			s.module = nil
		}
	})
}

type pkcs11Module struct {
	mu        sync.Mutex
	ctx       *pkcs11.Ctx
	backend   Backend
	module    string
	slotID    uint
	slotInfo  pkcs11.SlotInfo
	tokenInfo pkcs11.TokenInfo
	prompt    func(PromptInfo) (string, error)
	cleanup   func()
	refs      int
	closed    bool
}

func newPKCS11Module(cfg Options) (*pkcs11Module, error) {
	return newTokenModule(tokenModuleConfig{
		backend:    BackendPKCS11,
		modulePath: cfg.PKCS11Module,
		prompt:     cfg.CredentialPrompt,
		selectSlot: func(ctx *pkcs11.Ctx) (uint, pkcs11.SlotInfo, pkcs11.TokenInfo, error) {
			return selectPKCS11Slot(ctx, cfg.PKCS11Slot, cfg.PKCS11TokenLabel)
		},
	})
}

func newTokenModule(cfg tokenModuleConfig) (*pkcs11Module, error) {
	ctx := pkcs11.New(cfg.modulePath)
	if ctx == nil {
		if cfg.cleanup != nil {
			cfg.cleanup()
		}
		return nil, fmt.Errorf("loading pkcs11 module %q failed", cfg.modulePath)
	}

	cleanup := func() {
		_ = ctx.Finalize()
		ctx.Destroy()
		if cfg.cleanup != nil {
			cfg.cleanup()
		}
	}

	if err := ctx.Initialize(cfg.initOpts...); err != nil {
		ctx.Destroy()
		if cfg.cleanup != nil {
			cfg.cleanup()
		}
		return nil, fmt.Errorf("initializing %s module %q: %w", cfg.backend, cfg.modulePath, err)
	}

	slotID, slotInfo, tokenInfo, err := cfg.selectSlot(ctx)
	if err != nil {
		cleanup()
		return nil, err
	}

	return &pkcs11Module{
		backend:   cfg.backend,
		ctx:       ctx,
		module:    cfg.modulePath,
		slotID:    slotID,
		slotInfo:  slotInfo,
		tokenInfo: tokenInfo,
		prompt:    cfg.prompt,
		cleanup:   cfg.cleanup,
		refs:      1,
	}, nil
}

func (m *pkcs11Module) retain() (*pkcs11Module, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("pkcs11 module is closed")
	}
	m.refs++
	return m, nil
}

func (m *pkcs11Module) release() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.refs--
	if m.refs > 0 {
		return
	}
	m.closed = true
	_ = m.ctx.Finalize()
	m.ctx.Destroy()
	if m.cleanup != nil {
		m.cleanup()
		m.cleanup = nil
	}
	m.ctx = nil
}

func (m *pkcs11Module) openSession() (pkcs11.SessionHandle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, errors.New("pkcs11 module is closed")
	}
	return m.ctx.OpenSession(m.slotID, pkcs11.CKF_SERIAL_SESSION)
}

func (m *pkcs11Module) closeSession(session pkcs11.SessionHandle) {
	m.mu.Lock()
	ctx := m.ctx
	closed := m.closed
	m.mu.Unlock()
	if closed || ctx == nil {
		return
	}
	_ = ctx.CloseSession(session)
}

func (m *pkcs11Module) login(session pkcs11.SessionHandle) error {
	if m.tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED == 0 {
		return nil
	}
	if m.prompt == nil {
		return ErrCredentialRequired
	}

	pin, err := m.prompt(PromptInfo{
		Backend:    m.backend,
		TokenLabel: strings.TrimSpace(m.tokenInfo.Label),
		SlotID:     m.slotID,
		Reason:     string(m.backend) + " login required",
	})
	if err != nil {
		return err
	}
	err = m.ctx.Login(session, pkcs11.CKU_USER, pin)
	if err == nil {
		return nil
	}
	switch {
	case isPKCS11Error(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN):
		return nil
	case isPKCS11Error(err, pkcs11.CKR_PIN_INCORRECT), isPKCS11Error(err, pkcs11.CKR_PIN_INVALID):
		return ErrIncorrectCredential
	case isPKCS11Error(err, pkcs11.CKR_PIN_LEN_RANGE), isPKCS11Error(err, pkcs11.CKR_PIN_EXPIRED), isPKCS11Error(err, pkcs11.CKR_PIN_LOCKED):
		return fmt.Errorf("%w: %v", ErrCredentialRequired, err)
	default:
		return fmt.Errorf("%w: %v", ErrLoginRequired, err)
	}
}

func (m *pkcs11Module) hasPrivateKey(session pkcs11.SessionHandle, keyID []byte, label string) (bool, error) {
	if len(keyID) > 0 {
		objects, err := findPKCS11Objects(m.ctx, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, keyID),
		})
		if err != nil {
			return false, err
		}
		if len(objects) > 0 {
			return true, nil
		}
	}
	if label != "" {
		objects, err := findPKCS11Objects(m.ctx, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		})
		if err != nil {
			return false, err
		}
		if len(objects) > 0 {
			return true, nil
		}
	}
	return false, nil
}

type pkcs11CertificateObject struct {
	raw   []byte
	cert  *x509.Certificate
	keyID []byte
	label string
}

type pkcs11Identity struct {
	module    *pkcs11Module
	certDER   []byte
	keyID     []byte
	label     string
	chainPool []*x509.Certificate
	once      sync.Once
	cert      *x509.Certificate
	certErr   error
	closeOnce sync.Once
}

func (id *pkcs11Identity) Certificate() (*x509.Certificate, error) {
	id.once.Do(func() {
		id.cert, id.certErr = x509.ParseCertificate(id.certDER)
	})
	return id.cert, id.certErr
}

func (id *pkcs11Identity) CertificateChain() ([]*x509.Certificate, error) {
	cert, err := id.Certificate()
	if err != nil {
		return nil, err
	}
	return buildCertificateChain(cert, id.chainPool), nil
}

func (id *pkcs11Identity) Signer() (crypto.Signer, error) {
	moduleRef, err := id.module.retain()
	if err != nil {
		return nil, err
	}

	session, err := moduleRef.openSession()
	if err != nil {
		moduleRef.release()
		return nil, err
	}

	key, err := id.findPrivateKey(moduleRef, session, false)
	if err != nil && isPKCS11Error(err, pkcs11.CKR_USER_NOT_LOGGED_IN) {
		err = nil
	}
	if err != nil && !errors.Is(err, ErrIdentityNotFound) {
		moduleRef.closeSession(session)
		moduleRef.release()
		return nil, err
	}
	if key == 0 {
		if err := moduleRef.login(session); err != nil {
			moduleRef.closeSession(session)
			moduleRef.release()
			return nil, err
		}
		key, err = id.findPrivateKey(moduleRef, session, true)
		if err != nil {
			moduleRef.closeSession(session)
			moduleRef.release()
			return nil, err
		}
	}

	cert, err := id.Certificate()
	if err != nil {
		moduleRef.closeSession(session)
		moduleRef.release()
		return nil, err
	}

	signer := &pkcs11Signer{
		module:  moduleRef,
		session: session,
		key:     key,
		pub:     cert.PublicKey,
	}
	runtime.SetFinalizer(signer, (*pkcs11Signer).release)
	return signer, nil
}

func (id *pkcs11Identity) findPrivateKey(module *pkcs11Module, session pkcs11.SessionHandle, retryWithLabel bool) (pkcs11.ObjectHandle, error) {
	if len(id.keyID) > 0 {
		objects, err := findPKCS11Objects(module.ctx, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_ID, id.keyID),
		})
		if err != nil {
			return 0, err
		}
		if len(objects) > 0 {
			return objects[0], nil
		}
	}
	if retryWithLabel && id.label != "" {
		objects, err := findPKCS11Objects(module.ctx, session, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, id.label),
		})
		if err != nil {
			return 0, err
		}
		if len(objects) > 0 {
			return objects[0], nil
		}
	}
	return 0, ErrIdentityNotFound
}

func (id *pkcs11Identity) Close() {
	id.closeOnce.Do(func() {
		if id.module != nil {
			id.module.release()
			id.module = nil
		}
	})
}

func (id *pkcs11Identity) Label() string {
	return id.label
}

func (id *pkcs11Identity) Backend() Backend {
	return BackendPKCS11
}

func (id *pkcs11Identity) KeyType() string {
	cert, err := id.Certificate()
	if err != nil {
		return ""
	}
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

func (id *pkcs11Identity) IsHardwareBacked() bool {
	return id.module.slotInfo.Flags&pkcs11.CKF_HW_SLOT != 0
}

func (id *pkcs11Identity) RequiresLogin() bool {
	return id.module.tokenInfo.Flags&pkcs11.CKF_LOGIN_REQUIRED != 0
}

func (id *pkcs11Identity) HardwareBackedState() CapabilityState {
	if id.IsHardwareBacked() {
		return CapabilityYes
	}
	return CapabilityNo
}

func (id *pkcs11Identity) LoginRequiredState() CapabilityState {
	if id.RequiresLogin() {
		return CapabilityYes
	}
	return CapabilityNo
}

func (id *pkcs11Identity) URI() string {
	parts := []string{
		"module=" + id.module.module,
		fmt.Sprintf("slot=%d", id.module.slotID),
	}
	if label := strings.TrimSpace(id.module.tokenInfo.Label); label != "" {
		parts = append(parts, "token="+label)
	}
	if len(id.keyID) > 0 {
		parts = append(parts, "id="+hex.EncodeToString(id.keyID))
	} else if id.label != "" {
		parts = append(parts, "label="+id.label)
	}
	return "pkcs11:" + strings.Join(parts, ";")
}

func (id *pkcs11Identity) ModulePath() string {
	return id.module.module
}

func (id *pkcs11Identity) SlotID() uint {
	return id.module.slotID
}

func (id *pkcs11Identity) TokenLabel() string {
	return strings.TrimSpace(id.module.tokenInfo.Label)
}

func (id *pkcs11Identity) TokenSerial() string {
	return strings.TrimSpace(id.module.tokenInfo.SerialNumber)
}

type pkcs11Signer struct {
	mu      sync.Mutex
	module  *pkcs11Module
	session pkcs11.SessionHandle
	key     pkcs11.ObjectHandle
	pub     crypto.PublicKey
}

func (s *pkcs11Signer) Public() crypto.PublicKey {
	return s.pub
}

func (s *pkcs11Signer) supportedSignatureAlgorithms() []tls.SignatureScheme {
	return supportedSignatureAlgorithmsForPublicKey(s.pub)
}

func (s *pkcs11Signer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	runtime.SetFinalizer(s, nil)
	if s.module == nil {
		return nil
	}
	s.release()
	return nil
}

func (s *pkcs11Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.module == nil {
		return nil, ErrClosed
	}

	mech, input, err := pkcs11SignatureMechanism(s.pub, digest, opts)
	if err != nil {
		return nil, err
	}

	if err := s.module.ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.key); err != nil {
		if isPKCS11Error(err, pkcs11.CKR_USER_NOT_LOGGED_IN) {
			if loginErr := s.module.login(s.session); loginErr != nil {
				return nil, loginErr
			}
			if err := s.module.ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.key); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMechanismUnsupported, err)
			}
		} else {
			return nil, fmt.Errorf("%w: %v", ErrMechanismUnsupported, err)
		}
	}

	sig, err := s.module.ctx.Sign(s.session, input)
	if err != nil {
		if isPKCS11Error(err, pkcs11.CKR_USER_NOT_LOGGED_IN) {
			if loginErr := s.module.login(s.session); loginErr != nil {
				return nil, loginErr
			}
			if err := s.module.ctx.SignInit(s.session, []*pkcs11.Mechanism{mech}, s.key); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrMechanismUnsupported, err)
			}
			sig, err = s.module.ctx.Sign(s.session, input)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMechanismUnsupported, err)
		}
	}

	if ecPub, ok := s.pub.(*ecdsa.PublicKey); ok {
		return ecdsaRawToASN1(sig, ecPub)
	}
	return sig, nil
}

func (s *pkcs11Signer) release() {
	if s.module != nil {
		s.module.closeSession(s.session)
		s.module.release()
		s.module = nil
		s.session = 0
	}
}

func findPKCS11Objects(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, template []*pkcs11.Attribute) ([]pkcs11.ObjectHandle, error) {
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, err
	}
	defer func() {
		_ = ctx.FindObjectsFinal(session)
	}()

	var objects []pkcs11.ObjectHandle
	for {
		matches, _, err := ctx.FindObjects(session, 64)
		if err != nil {
			return nil, err
		}
		if len(matches) == 0 {
			return objects, nil
		}
		objects = append(objects, matches...)
	}
}

func selectPKCS11Slot(ctx *pkcs11.Ctx, slotSelection *uint, tokenLabel string) (uint, pkcs11.SlotInfo, pkcs11.TokenInfo, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("listing pkcs11 slots: %w", err)
	}
	if len(slots) == 0 {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, ErrIdentityNotFound
	}

	if slotSelection != nil {
		slotInfo, err := ctx.GetSlotInfo(*slotSelection)
		if err != nil {
			return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("reading pkcs11 slot %d: %w", *slotSelection, err)
		}
		tokenInfo, err := ctx.GetTokenInfo(*slotSelection)
		if err != nil {
			return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("reading pkcs11 token %d: %w", *slotSelection, err)
		}
		if tokenLabel != "" && strings.TrimSpace(tokenInfo.Label) != tokenLabel {
			return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("pkcs11 slot %d token label %q does not match requested %q", *slotSelection, strings.TrimSpace(tokenInfo.Label), tokenLabel)
		}
		return *slotSelection, slotInfo, tokenInfo, nil
	}

	for _, slotID := range slots {
		slotInfo, err := ctx.GetSlotInfo(slotID)
		if err != nil {
			continue
		}
		tokenInfo, err := ctx.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		if tokenLabel != "" && strings.TrimSpace(tokenInfo.Label) != tokenLabel {
			continue
		}
		return slotID, slotInfo, tokenInfo, nil
	}

	if tokenLabel != "" {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("%w: token %q", ErrIdentityNotFound, tokenLabel)
	}
	return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("%w: no usable pkcs11 slot found", ErrIdentityNotFound)
}

func pkcs11SignatureMechanism(pub crypto.PublicKey, digest []byte, opts crypto.SignerOpts) (*pkcs11.Mechanism, []byte, error) {
	hash := opts.HashFunc()

	switch pub.(type) {
	case *rsa.PublicKey:
		if pss, ok := opts.(*rsa.PSSOptions); ok {
			params, err := pkcs11PSSParams(hash, pss)
			if err != nil {
				return nil, nil, err
			}
			return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS_PSS, params), digest, nil
		}
		encoded, err := rsaPKCS1DigestInfo(hash, digest)
		if err != nil {
			return nil, nil, err
		}
		return pkcs11.NewMechanism(pkcs11.CKM_RSA_PKCS, nil), encoded, nil
	case *ecdsa.PublicKey:
		switch hash {
		case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
			return pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil), digest, nil
		default:
			return nil, nil, ErrUnsupportedHash
		}
	default:
		return nil, nil, fmt.Errorf("%w: unsupported public key %T", ErrMechanismUnsupported, pub)
	}
}

func pkcs11PSSParams(hash crypto.Hash, opts *rsa.PSSOptions) ([]byte, error) {
	hashAlg, mgf, err := pkcs11HashParams(hash)
	if err != nil {
		return nil, err
	}

	saltLength := opts.SaltLength
	switch saltLength {
	case rsa.PSSSaltLengthAuto, rsa.PSSSaltLengthEqualsHash:
		saltLength = hash.Size()
	}
	return pkcs11.NewPSSParams(hashAlg, mgf, uint(saltLength)), nil
}

func pkcs11HashParams(hash crypto.Hash) (uint, uint, error) {
	switch hash {
	case crypto.SHA1:
		return pkcs11.CKM_SHA_1, pkcs11.CKG_MGF1_SHA1, nil
	case crypto.SHA256:
		return pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, nil
	case crypto.SHA384:
		return pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, nil
	case crypto.SHA512:
		return pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, nil
	default:
		return 0, 0, ErrUnsupportedHash
	}
}

func rsaPKCS1DigestInfo(hash crypto.Hash, digest []byte) ([]byte, error) {
	oid, err := hashOID(hash)
	if err != nil {
		return nil, err
	}
	type digestInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		Digest    []byte
	}
	return asn1.Marshal(digestInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oid,
			Parameters: asn1.NullRawValue,
		},
		Digest: digest,
	})
}

func hashOID(hash crypto.Hash) (asn1.ObjectIdentifier, error) {
	switch hash {
	case crypto.SHA1:
		return asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}, nil
	case crypto.SHA256:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, nil
	case crypto.SHA384:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}, nil
	case crypto.SHA512:
		return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}, nil
	default:
		return nil, ErrUnsupportedHash
	}
}

func ecdsaRawToASN1(raw []byte, pub *ecdsa.PublicKey) ([]byte, error) {
	keySize := (pub.Curve.Params().BitSize + 7) / 8
	if len(raw) != 2*keySize {
		return nil, fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(raw), 2*keySize)
	}

	type ecdsaSig struct {
		R, S *big.Int
	}

	r := new(big.Int).SetBytes(raw[:keySize])
	s := new(big.Int).SetBytes(raw[keySize:])
	return asn1.Marshal(ecdsaSig{R: r, S: s})
}

func isPKCS11Error(err error, code uint) bool {
	var pkErr pkcs11.Error
	if !errors.As(err, &pkErr) {
		return false
	}
	return uint(pkErr) == code
}

func cloneBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func buildCertificateChain(leaf *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	if leaf == nil {
		return nil
	}

	chain := []*x509.Certificate{leaf}
	seen := map[string]struct{}{
		string(leaf.Raw): {},
	}
	current := leaf

	for {
		issuer := findIssuerCertificate(current, candidates, seen)
		if issuer == nil {
			break
		}
		chain = append(chain, issuer)
		seen[string(issuer.Raw)] = struct{}{}
		if bytes.Equal(issuer.RawSubject, issuer.RawIssuer) {
			break
		}
		current = issuer
	}

	return chain
}

func findIssuerCertificate(cert *x509.Certificate, candidates []*x509.Certificate, seen map[string]struct{}) *x509.Certificate {
	if cert == nil || bytes.Equal(cert.RawSubject, cert.RawIssuer) {
		return nil
	}

	if len(cert.AuthorityKeyId) > 0 {
		for _, candidate := range candidates {
			if candidate == nil {
				continue
			}
			if _, ok := seen[string(candidate.Raw)]; ok {
				continue
			}
			if bytes.Equal(candidate.RawSubject, cert.RawIssuer) && len(candidate.SubjectKeyId) > 0 && bytes.Equal(candidate.SubjectKeyId, cert.AuthorityKeyId) {
				return candidate
			}
		}
	}

	for _, candidate := range candidates {
		if candidate == nil {
			continue
		}
		if _, ok := seen[string(candidate.Raw)]; ok {
			continue
		}
		if bytes.Equal(candidate.RawSubject, cert.RawIssuer) {
			return candidate
		}
	}

	return nil
}

var (
	_ IdentityInfo       = (*pkcs11Identity)(nil)
	_ PKCS11IdentityInfo = (*pkcs11Identity)(nil)
	_ CloseableSigner    = (*pkcs11Signer)(nil)
	_                    = elliptic.P256
)
