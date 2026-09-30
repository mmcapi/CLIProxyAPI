package auth

import (
	"context"
	"errors"
	"testing"
)

func TestManagedReleasePreservesInertFreeFiles(t *testing.T) {
	a := &Auth{Provider: "free", Metadata: map[string]any{"type": "free", "refresh_token": "fixture"}, Attributes: map[string]string{AttributeSourceBackend: AuthSourceFile}}
	if err := ValidateManagedCredential(a); err != nil {
		t.Fatalf("inert legacy file rejected: %v", err)
	}
	for _, key := range []string{"base_url", "api_key", "compat_name", "provider_key"} {
		candidate := a.Clone()
		candidate.Attributes[key] = "configured"
		if ValidateManagedCredential(candidate) == nil {
			t.Fatalf("accepted routed free attribute %s", key)
		}
	}
	if ValidateManagedCredential(&Auth{Provider: "free"}) == nil {
		t.Fatal("accepted non-file free credential")
	}
}

func TestManagedReleaseFreeCannotExecuteOrRefresh(t *testing.T) {
	m := NewManager(nil, nil, nil)
	exec := &countingRefreshExecutor{id: "free"}
	m.RegisterExecutor(exec)
	if _, ok := m.Executor("free"); !ok {
		t.Fatal("standalone behavior changed")
	}
	m.SetRefreshGate(&observedRefreshGate{})
	a := &Auth{ID: "free.json", Provider: "free", Attributes: map[string]string{AttributeSourceBackend: AuthSourceFile}}
	if _, err := m.Register(WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Executor("free"); ok {
		t.Fatal("inert provider executor remained available")
	}
	if _, err := m.ForceRefreshAuth(context.Background(), a.ID); err == nil {
		t.Fatal("inert provider refresh succeeded")
	}
	if len(m.List()) != 1 {
		t.Fatal("inert record disappeared from management")
	}
}

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
