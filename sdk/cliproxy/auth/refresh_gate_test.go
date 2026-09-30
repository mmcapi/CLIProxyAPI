package auth

import (
	"context"
	"errors"
	"testing"
)

type observedRefreshGate struct {
	entered, released bool
	reject            bool
}

func (g *observedRefreshGate) Enter(context.Context) (func(), error) {
	if g.reject {
		return nil, errors.New("not owner")
	}
	g.entered = true
	return func() { g.released = true }, nil
}

type gateCheckingStore struct {
	gate    *observedRefreshGate
	checked bool
}

func (s *gateCheckingStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *gateCheckingStore) Delete(context.Context, string) error  { return nil }
func (s *gateCheckingStore) Save(_ context.Context, _ *Auth) (string, error) {
	if s.gate != nil {
		if !s.gate.entered || s.gate.released {
			return "", errors.New("persistence outside ownership")
		}
		s.checked = true
	}
	return "auth.json", nil
}
func TestRefreshGateCoversSyncBackgroundAndPersistence(t *testing.T) {
	ctx := context.Background()
	gate := &observedRefreshGate{reject: true}
	store := &gateCheckingStore{}
	m := NewManager(store, nil, nil)
	executor := &countingRefreshExecutor{id: "codex"}
	m.RegisterExecutor(executor)
	if _, err := m.Register(ctx, &Auth{ID: "owned", Provider: "codex", Metadata: map[string]any{"refresh_token": "test"}}); err != nil {
		t.Fatal(err)
	}
	m.SetRefreshGate(gate)
	if _, err := m.ForceRefreshAuth(ctx, "owned"); err == nil {
		t.Fatal("sync refresh admitted")
	}
	m.refreshAuth(ctx, "owned")
	if executor.refreshCalls.Load() != 0 {
		t.Fatal("background refresh admitted")
	}
	gate.reject = false
	store.gate = gate
	if _, err := m.ForceRefreshAuth(ctx, "owned"); err != nil {
		t.Fatal(err)
	}
	if !store.checked || !gate.released {
		t.Fatal("gate not held across persistence and released afterward")
	}
}
