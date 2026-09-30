package pluginhost

import (
	"context"
	"strings"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/roombridge"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestOptimizationExecutionAuth(t *testing.T) {
	now := time.Unix(1800000000, 0)
	key := strings.Repeat("k", 32)
	t.Setenv(roombridge.KeyEnv, key)
	host := newHostWithRecords(normalizeTestCapabilityRecord(capabilityRecord{id: "installation-uuid", meta: pluginapi.Metadata{Name: "oai-basispoints-cpa"}}))
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	account := &coreauth.Auth{ID: "native.json", Provider: "codex", Prefix: "source", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "test-only"}}
	account.EnsureIndex()
	if _, err := manager.Register(context.Background(), account); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"source/gpt-6-astra"}`)
	claims := roombridge.Claims{Version: 1, RoomID: "room", AccountID: "account", Prefix: "source", AuthIndex: account.Index, Model: "gpt-6-astra", Enabled: true, RequestID: "unique", PolicyVersion: 1}
	var selectedID, selectedIndex string
	opts := coreexecutor.Options{OriginalRequest: body, Metadata: map[string]any{coreexecutor.SelectedAuthCallbackMetadataKey: func(id string) { selectedID = id }, coreexecutor.SelectedAuthIndexCallbackMetadataKey: func(id string) { selectedIndex = id }}}
	var err error
	opts.Headers, err = roombridge.Sign([]byte(key), claims, body, now)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := host.optimizationExecutionAuth("installation-uuid", opts, now)
	if err != nil || selected == nil {
		t.Fatalf("selection: %v", err)
	}
	if selectedID != account.ID || selectedIndex != account.Index || opts.Metadata["mmc_optimization_auth_index"] != account.Index || selected.Metadata["access_token"] != "test-only" {
		t.Fatal("selected auth evidence or metadata lost")
	}
	if _, err := host.optimizationExecutionAuth("other", opts, now); err == nil {
		t.Fatal("accepted wrong plugin")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*coreauth.Auth)
	}{
		{"disabled", func(a *coreauth.Auth) { a.Disabled = true }},
		{"unavailable", func(a *coreauth.Auth) { a.Unavailable = true }},
		{"error", func(a *coreauth.Auth) { a.Status = coreauth.StatusError }},
		{"prefix", func(a *coreauth.Auth) { a.Prefix = "other" }},
		{"provider", func(a *coreauth.Auth) { a.Provider = "other" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := account.Clone()
			tc.mutate(changed)
			if _, err := manager.Update(context.Background(), changed); err != nil {
				t.Fatal(err)
			}
			if _, err := host.optimizationExecutionAuth("installation-uuid", opts, now); err == nil {
				t.Fatal("accepted invalid source")
			}
			if _, err := manager.Update(context.Background(), account); err != nil {
				t.Fatal(err)
			}
		})
	}
	claims.AuthIndex = "wrong-index"
	opts.Headers, _ = roombridge.Sign([]byte(key), claims, body, now)
	if _, err := host.optimizationExecutionAuth("installation-uuid", opts, now); err == nil {
		t.Fatal("accepted wrong index")
	}
	opts.Headers = nil
	if auth, err := host.optimizationExecutionAuth("ordinary", opts, now); err != nil || auth != nil {
		t.Fatal("unsigned route changed")
	}
}

func TestOptimizationExecutionDispatchPreservesNativeAuth(t *testing.T) {
	key := strings.Repeat("k", 32)
	t.Setenv(roombridge.KeyEnv, key)
	var observed pluginapi.ExecutorRequest
	executor := &fakeExecutor{identifier: "bps", execute: func(_ context.Context, req pluginapi.ExecutorRequest) (pluginapi.ExecutorResponse, error) {
		observed = req
		return pluginapi.ExecutorResponse{Payload: []byte(`{"choices":[]}`)}, nil
	}}
	host := newHostWithRecords(capabilityRecord{id: "installed-id", meta: pluginapi.Metadata{Name: "oai-basispoints-cpa"}, plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{Executor: executor, ExecutorInputFormats: []string{"openai"}, ExecutorOutputFormats: []string{"openai"}}}})
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	auth := &coreauth.Auth{ID: "native.json", Provider: "codex", Prefix: "source", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "test-only"}, Storage: &memoryAuthStorage{payload: []byte(`{"access_token":"test-only"}`)}}
	auth.EnsureIndex()
	if _, err := manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"model":"source/gpt-6-astra","messages":[]}`)
	headers, err := roombridge.Sign([]byte(key), roombridge.Claims{Version: 1, RoomID: "room", AccountID: "account", Prefix: "source", AuthIndex: auth.Index, Model: "gpt-6-astra", Enabled: true, RequestID: "unique", PolicyVersion: 1}, body, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	opts := coreexecutor.Options{Headers: headers, OriginalRequest: body, SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI}
	if _, err := host.ExecutePluginExecutor(context.Background(), "installed-id", coreexecutor.Request{Model: "source/gpt-6-astra", Payload: body}, opts); err != nil {
		t.Fatal(err)
	}
	if observed.AuthID != auth.ID || observed.AuthProvider != "codex" || observed.Metadata["mmc_optimization_auth_index"] != auth.Index || observed.AuthMetadata["access_token"] != "test-only" || string(observed.StorageJSON) != `{"access_token":"test-only"}` {
		t.Fatalf("native source lost in plugin dispatch: %+v", observed)
	}
	opts.Headers = nil
	if _, err := host.ExecutePluginExecutor(context.Background(), "installed-id", coreexecutor.Request{Model: "gpt-6-astra", Payload: body}, opts); err != nil {
		t.Fatal(err)
	}
	if observed.AuthID != "" || len(observed.StorageJSON) != 0 {
		t.Fatal("unsigned request received native auth")
	}
}

func TestOptimizationActivitySurvivesCancellationAndCallbackCleanup(t *testing.T) {
	host := New()
	instance := &hostCallbackInstance{}
	adapter := &rpcPluginAdapter{host: host, id: "installation", instance: instance}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), optimizationExecutionKey{}, true))
	id, cleanup := host.openCallbackContextForPluginInstance(ctx, adapter.id, instance)
	adapter.reserveOptimization(ctx, id)
	request := []byte(`{"host_callback_id":"` + id + `"}`)
	caller := withHostCallbackIdentity(context.Background(), adapter.id, instance)
	if result, err := host.callOptimizationActivity(caller, request, false); err != nil || !strings.Contains(string(result), `"result":{"cancelled":false}`) {
		t.Fatalf("state %s %v", result, err)
	}
	cancel()
	cleanup()
	if host.OptimizationActive() != 1 {
		t.Fatal("cancellation released active upstream work")
	}
	if _, err := host.callOptimizationActivity(withHostCallbackIdentity(context.Background(), "other", instance), request, true); err == nil {
		t.Fatal("foreign plugin closed lease")
	}
	if result, err := host.callOptimizationActivity(caller, request, false); err != nil || !strings.Contains(string(result), `"result":{"cancelled":true}`) {
		t.Fatalf("cancelled state %s %v", result, err)
	}
	if _, err := host.callOptimizationActivity(caller, request, true); err != nil {
		t.Fatal(err)
	}
	if host.OptimizationActive() != 0 {
		t.Fatal("cleanup acknowledgement did not release lease")
	}
}
