package cliproxy

import (
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"testing"
)

type releaseFixtureStore struct{ items []*coreauth.Auth }

func (s *releaseFixtureStore) List(context.Context) ([]*coreauth.Auth, error)       { return s.items, nil }
func (s *releaseFixtureStore) Save(context.Context, *coreauth.Auth) (string, error) { return "", nil }
func (s *releaseFixtureStore) Delete(context.Context, string) error                 { return nil }

func TestReleaseQueuedWatcherUpdatesUseDurableCredentials(t *testing.T) {
	durable := &coreauth.Auth{ID: "account.json", Provider: "codex", Metadata: map[string]any{"access_token": "latest"}}
	store := &releaseFixtureStore{items: []*coreauth.Auth{durable}}
	service := &Service{releaseAuthStore: store}
	stale := durable.Clone()
	stale.Metadata["access_token"] = "stale"
	for _, action := range []watcher.AuthUpdateAction{watcher.AuthUpdateActionAdd, watcher.AuthUpdateActionModify, watcher.AuthUpdateActionDelete} {
		got, err := service.authoritativeReleaseUpdates(context.Background(), []watcher.AuthUpdate{{Action: action, ID: stale.ID, Auth: stale}})
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Action != watcher.AuthUpdateActionModify || got[0].Auth.Metadata["access_token"] != "latest" {
			t.Fatal("queued stale snapshot won over disk")
		}
	}
	store.items = nil
	got, err := service.authoritativeReleaseUpdates(context.Background(), []watcher.AuthUpdate{{Action: watcher.AuthUpdateActionAdd, Auth: stale}})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Action != watcher.AuthUpdateActionDelete || got[0].Auth != nil {
		t.Fatal("queued add resurrected deleted credential")
	}
}

func TestReleaseActivationRetainsConfiguredAPIKeys(t *testing.T) {
	ctx := context.Background()
	store := &releaseFixtureStore{items: []*coreauth.Auth{{ID: "file.json", Provider: "codex", Metadata: map[string]any{"access_token": "fresh"}}}}
	manager := coreauth.NewManager(store, nil, nil)
	service := &Service{coreManager: manager, cfg: &config.Config{CodexKey: []config.CodexKey{{APIKey: "fixture-config-api-key", Models: []config.CodexModel{{Name: "gpt-6-astra"}}}}}}
	service.registerConfigAPIKeyAuths(coreauth.WithSkipPersist(ctx), service.cfg)
	if len(manager.List()) != 1 {
		t.Fatal("configured auth fixture missing")
	}
	if err := service.reloadReleaseCredentials(ctx); err != nil {
		t.Fatal(err)
	}
	auths := manager.List()
	if len(auths) != 2 {
		t.Fatalf("activation lost configured auth: count=%d", len(auths))
	}
	configured := 0
	for _, auth := range auths {
		if coreauth.IsConfigAPIKeyAuth(auth) {
			configured++
		}
	}
	if configured != 1 {
		t.Fatal("configured key not restored")
	}
}

func TestReleaseUnsupportedRotatingProviderRejected(t *testing.T) {
	for _, provider := range []string{"meta", "antigravity", "claude"} {
		if coreauth.ValidateManagedCredential(&coreauth.Auth{Provider: provider}) == nil {
			t.Fatalf("accepted %s", provider)
		}
	}
}
