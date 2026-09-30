package cliproxy

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/releasecontrol"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/watcher"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (s *Service) prepareReleaseController(ctx context.Context) (*releasecontrol.Controller, error) {
	path := strings.TrimSpace(os.Getenv("MMC_RELEASE_LOCK_FILE"))
	token := os.Getenv("MMC_RELEASE_CONTROL_TOKEN")
	if path == "" && token == "" {
		return nil, nil
	}
	if path == "" || len(token) < 32 {
		return nil, errors.New("managed release requires lock file and control token of at least 32 bytes")
	}
	if s.cfg.Home.Enabled {
		return nil, errors.New("managed releases require standalone file auth storage")
	}
	store, ok := sdkAuth.GetTokenStore().(*sdkAuth.FileTokenStore)
	if !ok {
		return nil, errors.New("managed releases require FileTokenStore")
	}
	owner, err := releasecontrol.NewOwner(path)
	if err != nil {
		return nil, err
	}
	s.coreManager.SetRefreshGate(owner)
	store.SetCredentialWriteGate(owner)
	s.releaseAuthStore = store
	items, err := store.List(ctx)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if err := coreauth.ValidateManagedCredential(item); err != nil {
			return nil, err
		}
	}
	reload := func() error {
		s.authUpdateMu.Lock()
		defer s.authUpdateMu.Unlock()
		return s.reloadReleaseCredentials(ctx)
	}
	active := func() int64 {
		if s.pluginHost == nil {
			return 0
		}
		return int64(s.pluginHost.OptimizationActive())
	}
	return releasecontrol.NewController(owner, token, reload, active, s.coreManager.ReleaseExecutionsActive), nil
}

func (s *Service) reloadReleaseCredentials(ctx context.Context) error {
	if err := s.coreManager.Load(ctx); err != nil {
		return err
	}
	s.cfgMu.RLock()
	cfg := s.cfg
	s.cfgMu.RUnlock()
	s.registerConfigAPIKeyAuths(coreauth.WithSkipPersist(ctx), cfg)
	return nil
}

// authoritativeReleaseUpdates replaces queued filesystem snapshots with current
// durable data. The caller holds authUpdateMu, also held by activation reload.
func (s *Service) authoritativeReleaseUpdates(ctx context.Context, updates []watcher.AuthUpdate) ([]watcher.AuthUpdate, error) {
	if s.releaseAuthStore == nil {
		return updates, nil
	}
	items, err := s.releaseAuthStore.List(ctx)
	if err != nil {
		return nil, err
	}
	current := make(map[string]*coreauth.Auth, len(items))
	for _, item := range items {
		if item != nil {
			current[item.ID] = item
		}
	}
	out := make([]watcher.AuthUpdate, 0, len(updates))
	for _, update := range updates {
		if update.Auth != nil && coreauth.IsConfigAPIKeyAuth(update.Auth) {
			out = append(out, update)
			continue
		}
		id := authUpdateID(update)
		if item := current[id]; item != nil {
			if err := coreauth.ValidateManagedCredential(item); err != nil {
				return nil, err
			}
			update.Action = watcher.AuthUpdateActionModify
			update.Auth = item.Clone()
		} else {
			update.Action = watcher.AuthUpdateActionDelete
			update.Auth = nil
			update.ID = id
		}
		out = append(out, update)
	}
	return out, nil
}
