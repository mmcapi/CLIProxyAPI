package auth

import (
	"context"
	"fmt"
	"strings"
)

// ValidateManagedCredential bounds release ownership support to Codex OAuth
// and the linked optimization provider. Configured API keys do not rotate.
func ValidateManagedCredential(auth *Auth) error {
	if auth == nil || IsConfigAPIKeyAuth(auth) {
		return nil
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider != "codex" && provider != "bps" {
		return fmt.Errorf("managed releases do not support credential provider %q", provider)
	}
	return nil
}

type refreshGateHolder struct{ gate RefreshGate }

func (m *Manager) credentialGate() RefreshGate {
	if holder := m.refreshGate.Load(); holder != nil {
		return holder.gate
	}
	return nil
}

// AdmitCredentialMutation preserves a scoped admission through nested stores.
func AdmitCredentialMutation(ctx context.Context, gate RefreshGate) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if gate == nil {
		return ctx, func() {}, nil
	}
	if scoped, ok := gate.(interface {
		EnterContext(context.Context) (context.Context, func(), error)
	}); ok {
		return scoped.EnterContext(ctx)
	}
	release, err := gate.Enter(ctx)
	return ctx, release, err
}

// RefreshGate owns cross-process refresh admission. A release callback must stay
// held until token persistence completes, including failure paths.
type RefreshGate interface {
	Enter(context.Context) (func(), error)
}

// SetRefreshGate must be called before starting the service or refresh workers.
// A nil gate preserves the standalone behavior.
func (m *Manager) SetRefreshGate(gate RefreshGate) {
	m.refreshGate.Store(&refreshGateHolder{gate: gate})
}
