//go:build cgo

package certstore

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"unsafe"

	"github.com/sukujgrg/go-certstore/internal/pkcs11"
)

func openNSSStore(ctx context.Context, cfg Options) (Store, error) {
	module, err := newNSSModule(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &nssStore{
		store:       &pkcs11Store{module: module},
		profileDir:  cfg.NSSProfileDir,
		profileSpec: normalizeNSSProfileDir(cfg.NSSProfileDir),
	}, nil
}

type nssStore struct {
	store       *pkcs11Store
	profileDir  string
	profileSpec string
}

func (s *nssStore) Identities(ctx context.Context) ([]Identity, error) {
	idents, err := s.store.Identities(ctx)
	if err != nil {
		return nil, fmt.Errorf("list nss identities: %w", err)
	}

	wrapped := make([]Identity, 0, len(idents))
	for _, ident := range idents {
		tokenIdent, ok := ident.(*pkcs11Identity)
		if !ok {
			wrapped = append(wrapped, ident)
			continue
		}
		wrapped = append(wrapped, &nssIdentity{
			pkcs11Identity: tokenIdent,
			profileDir:     s.profileDir,
			profileSpec:    s.profileSpec,
		})
	}
	return wrapped, nil
}

func (s *nssStore) Close() {
	s.store.Close()
}

type nssIdentity struct {
	*pkcs11Identity
	profileDir  string
	profileSpec string
}

func (id *nssIdentity) Certificate(ctx context.Context) (*x509.Certificate, error) {
	return id.pkcs11Identity.Certificate(ctx)
}

func (id *nssIdentity) CertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	return id.pkcs11Identity.CertificateChain(ctx)
}

func (id *nssIdentity) Signer(ctx context.Context) (crypto.Signer, error) {
	signer, err := id.pkcs11Identity.Signer(ctx)
	if err != nil {
		return nil, fmt.Errorf("create nss signer: %w", err)
	}
	return signer, nil
}

func (id *nssIdentity) Close() {
	id.pkcs11Identity.Close()
}

func (id *nssIdentity) Label() string {
	if label := id.pkcs11Identity.Label(); label != "" {
		return label
	}
	cert, err := id.pkcs11Identity.Certificate(context.Background())
	if err != nil {
		return ""
	}
	if cert.Subject.CommonName != "" {
		return cert.Subject.CommonName
	}
	return cert.Subject.String()
}

func (id *nssIdentity) Backend() Backend {
	return BackendNSS
}

func (id *nssIdentity) KeyType() string {
	return id.pkcs11Identity.KeyType()
}

func (id *nssIdentity) IsHardwareBacked() bool {
	return id.pkcs11Identity.IsHardwareBacked()
}

func (id *nssIdentity) RequiresLogin() bool {
	return id.pkcs11Identity.RequiresLogin()
}

func (id *nssIdentity) HardwareBackedState() CapabilityState {
	return id.pkcs11Identity.HardwareBackedState()
}

func (id *nssIdentity) LoginRequiredState() CapabilityState {
	return id.pkcs11Identity.LoginRequiredState()
}

func (id *nssIdentity) URI() string {
	parts := []string{
		"profile=" + id.profileSpec,
		"module=" + id.pkcs11Identity.module.module,
	}
	if label := strings.TrimSpace(id.pkcs11Identity.module.tokenInfo.Label); label != "" {
		parts = append(parts, "token="+label)
	}
	if len(id.pkcs11Identity.keyID) > 0 {
		parts = append(parts, "id="+hex.EncodeToString(id.pkcs11Identity.keyID))
	} else if label := id.Label(); label != "" {
		parts = append(parts, "label="+label)
	}
	return "nss:" + strings.Join(parts, ";")
}

func (id *nssIdentity) ProfileDir() string {
	return id.profileDir
}

func (id *nssIdentity) ModulePath() string {
	return id.pkcs11Identity.module.module
}

func (id *nssIdentity) TokenLabel() string {
	return strings.TrimSpace(id.pkcs11Identity.module.tokenInfo.Label)
}

func (id *nssIdentity) TokenSerial() string {
	return strings.TrimSpace(id.pkcs11Identity.module.tokenInfo.SerialNumber)
}

func newNSSModule(ctx context.Context, cfg Options) (*pkcs11Module, error) {
	profileSpec := normalizeNSSProfileDir(cfg.NSSProfileDir)
	reserved := C.CString(fmt.Sprintf("configdir='%s' certPrefix='' keyPrefix='' secmod='secmod.db' flags=readOnly", profileSpec))
	cleanup := func() {
		C.free(unsafe.Pointer(reserved))
	}

	return newTokenModule(ctx, tokenModuleConfig{
		backend:    BackendNSS,
		modulePath: cfg.NSSModule,
		prompt:     cfg.CredentialPrompt,
		initOpts: []pkcs11.InitializeOption{
			pkcs11.InitializeWithReserved(unsafe.Pointer(reserved)),
		},
		cleanup:    cleanup,
		selectSlot: selectNSSSlot,
	})
}

func normalizeNSSProfileDir(dir string) string {
	switch {
	case strings.HasPrefix(dir, "sql:"):
		return dir
	case strings.HasPrefix(dir, "dbm:"):
		return dir
	default:
		return "sql:" + dir
	}
}

func selectNSSSlot(ctx context.Context, reader *pkcs11.Context) (uint, pkcs11.SlotInfo, pkcs11.TokenInfo, error) {
	return selectNSSSlotFromReader(ctx, reader)
}

func selectNSSSlotFromReader(ctx context.Context, reader pkcs11SlotReader) (uint, pkcs11.SlotInfo, pkcs11.TokenInfo, error) {
	ctx = normalizeContext(ctx)
	if err := ctx.Err(); err != nil {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, err
	}
	slots, err := reader.GetSlotList(true)
	if err != nil {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("listing nss slots: %w", err)
	}
	if len(slots) == 0 {
		return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, ErrIdentityNotFound
	}

	type candidate struct {
		slotID    uint
		slotInfo  pkcs11.SlotInfo
		tokenInfo pkcs11.TokenInfo
	}

	var firstNonGeneric *candidate
	var firstAny *candidate

	for _, slotID := range slots {
		if err := ctx.Err(); err != nil {
			return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, err
		}
		slotInfo, err := reader.GetSlotInfo(slotID)
		if err != nil {
			continue
		}
		tokenInfo, err := reader.GetTokenInfo(slotID)
		if err != nil {
			continue
		}
		c := &candidate{slotID: slotID, slotInfo: slotInfo, tokenInfo: tokenInfo}
		if firstAny == nil {
			firstAny = c
		}

		label := strings.TrimSpace(tokenInfo.Label)
		switch label {
		case "NSS Certificate DB", "NSS FIPS 140-2 Certificate DB":
			return slotID, slotInfo, tokenInfo, nil
		case "NSS Generic Crypto Services":
			continue
		default:
			if firstNonGeneric == nil {
				firstNonGeneric = c
			}
		}
	}

	if firstNonGeneric != nil {
		return firstNonGeneric.slotID, firstNonGeneric.slotInfo, firstNonGeneric.tokenInfo, nil
	}
	if firstAny != nil {
		return firstAny.slotID, firstAny.slotInfo, firstAny.tokenInfo, nil
	}
	return 0, pkcs11.SlotInfo{}, pkcs11.TokenInfo{}, fmt.Errorf("%w: no usable nss slot found", ErrIdentityNotFound)
}

var _ NSSIdentityInfo = (*nssIdentity)(nil)
