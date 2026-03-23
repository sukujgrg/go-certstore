package pkcs11

import (
	"bytes"
	"errors"

	upstream "github.com/miekg/pkcs11"
)

type miekgBackend struct{}

func (miekgBackend) open(path string) module {
	ctx := upstream.New(path)
	if ctx == nil {
		return nil
	}
	return &miekgModule{ctx: ctx}
}

func (miekgBackend) newPSSParams(hashAlg, mgf, saltLength uint) []byte {
	return bytes.Clone(upstream.NewPSSParams(hashAlg, mgf, saltLength))
}

type miekgModule struct {
	ctx *upstream.Ctx
}

func (m *miekgModule) Initialize(opts ...InitializeOption) error {
	upstreamOpts := make([]upstream.InitializeOption, 0, len(opts))
	for _, opt := range opts {
		if opt.reserved != nil {
			upstreamOpts = append(upstreamOpts, upstream.InitializeWithReserved(opt.reserved))
		}
	}
	return wrapError(m.ctx.Initialize(upstreamOpts...))
}

func (m *miekgModule) Finalize() error {
	return wrapError(m.ctx.Finalize())
}

func (m *miekgModule) Destroy() {
	m.ctx.Destroy()
}

func (m *miekgModule) OpenSession(slotID uint, flags uint) (SessionHandle, error) {
	session, err := m.ctx.OpenSession(slotID, flags)
	if err != nil {
		return 0, wrapError(err)
	}
	return SessionHandle(session), nil
}

func (m *miekgModule) CloseSession(session SessionHandle) error {
	return wrapError(m.ctx.CloseSession(upstream.SessionHandle(session)))
}

func (m *miekgModule) Login(session SessionHandle, userType uint, pin string) error {
	return wrapError(m.ctx.Login(upstream.SessionHandle(session), userType, pin))
}

func (m *miekgModule) Logout(session SessionHandle) error {
	return wrapError(m.ctx.Logout(upstream.SessionHandle(session)))
}

func (m *miekgModule) GetSlotList(tokenPresent bool) ([]uint, error) {
	slots, err := m.ctx.GetSlotList(tokenPresent)
	if err != nil {
		return nil, wrapError(err)
	}
	return slots, nil
}

func (m *miekgModule) GetSlotInfo(slotID uint) (SlotInfo, error) {
	info, err := m.ctx.GetSlotInfo(slotID)
	if err != nil {
		return SlotInfo{}, wrapError(err)
	}
	return SlotInfo{
		Flags: info.Flags,
	}, nil
}

func (m *miekgModule) GetTokenInfo(slotID uint) (TokenInfo, error) {
	info, err := m.ctx.GetTokenInfo(slotID)
	if err != nil {
		return TokenInfo{}, wrapError(err)
	}
	return TokenInfo{
		Label:        info.Label,
		SerialNumber: info.SerialNumber,
		Flags:        info.Flags,
	}, nil
}

func (m *miekgModule) GetAttributeValue(session SessionHandle, object ObjectHandle, attrs []*Attribute) ([]*Attribute, error) {
	values, err := m.ctx.GetAttributeValue(
		upstream.SessionHandle(session),
		upstream.ObjectHandle(object),
		toUpstreamAttributes(attrs),
	)
	if err != nil {
		return nil, wrapError(err)
	}
	return fromUpstreamAttributes(values), nil
}

func (m *miekgModule) FindObjectsInit(session SessionHandle, template []*Attribute) error {
	return wrapError(m.ctx.FindObjectsInit(upstream.SessionHandle(session), toUpstreamAttributes(template)))
}

func (m *miekgModule) FindObjects(session SessionHandle, max int) ([]ObjectHandle, bool, error) {
	objects, more, err := m.ctx.FindObjects(upstream.SessionHandle(session), max)
	if err != nil {
		return nil, false, wrapError(err)
	}
	return fromUpstreamObjectHandles(objects), more, nil
}

func (m *miekgModule) FindObjectsFinal(session SessionHandle) error {
	return wrapError(m.ctx.FindObjectsFinal(upstream.SessionHandle(session)))
}

func (m *miekgModule) SignInit(session SessionHandle, mechanisms []*Mechanism, key ObjectHandle) error {
	return wrapError(
		m.ctx.SignInit(
			upstream.SessionHandle(session),
			toUpstreamMechanisms(mechanisms),
			upstream.ObjectHandle(key),
		),
	)
}

func (m *miekgModule) Sign(session SessionHandle, data []byte) ([]byte, error) {
	signature, err := m.ctx.Sign(upstream.SessionHandle(session), data)
	if err != nil {
		return nil, wrapError(err)
	}
	return signature, nil
}

func toUpstreamAttributes(attrs []*Attribute) []*upstream.Attribute {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]*upstream.Attribute, 0, len(attrs))
	for _, attr := range attrs {
		if attr == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, &upstream.Attribute{
			Type:  attr.Type,
			Value: bytes.Clone(attr.Value),
		})
	}
	return out
}

func fromUpstreamAttributes(attrs []*upstream.Attribute) []*Attribute {
	if len(attrs) == 0 {
		return nil
	}
	out := make([]*Attribute, 0, len(attrs))
	for _, attr := range attrs {
		if attr == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, &Attribute{
			Type:  attr.Type,
			Value: bytes.Clone(attr.Value),
		})
	}
	return out
}

func toUpstreamMechanisms(mechanisms []*Mechanism) []*upstream.Mechanism {
	if len(mechanisms) == 0 {
		return nil
	}
	out := make([]*upstream.Mechanism, 0, len(mechanisms))
	for _, mech := range mechanisms {
		if mech == nil {
			out = append(out, nil)
			continue
		}
		out = append(out, upstream.NewMechanism(mech.Mechanism, cloneMechanismParameter(mech.Parameter)))
	}
	return out
}

func fromUpstreamObjectHandles(handles []upstream.ObjectHandle) []ObjectHandle {
	if len(handles) == 0 {
		return nil
	}
	out := make([]ObjectHandle, len(handles))
	for i, handle := range handles {
		out[i] = ObjectHandle(handle)
	}
	return out
}

func wrapError(err error) error {
	if err == nil {
		return nil
	}
	var pkErr upstream.Error
	if errors.As(err, &pkErr) {
		return Error(pkErr)
	}
	return err
}
