package certstore

func identityHardwareBackedState(ident Identity) CapabilityState {
	if info, ok := ident.(IdentityCapabilityInfo); ok {
		return info.HardwareBackedState()
	}
	if info, ok := ident.(IdentityInfo); ok {
		if info.IsHardwareBacked() {
			return CapabilityYes
		}
		return CapabilityNo
	}
	return CapabilityUnknown
}

func identityLoginRequiredState(ident Identity) CapabilityState {
	if info, ok := ident.(IdentityCapabilityInfo); ok {
		return info.LoginRequiredState()
	}
	if info, ok := ident.(IdentityInfo); ok {
		if info.RequiresLogin() {
			return CapabilityYes
		}
		return CapabilityNo
	}
	return CapabilityUnknown
}
