package pluginhost

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/roombridge"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// This opt-in contract test loads the separately built C ABI plugin. Every
// upstream request goes to this process's loopback fixture, never a real account.
func TestOptimizationLibraryRoundTrip(t *testing.T) {
	library := os.Getenv("MMC_OPTIMIZATION_TEST_LIBRARY")
	if library == "" {
		t.Skip("set MMC_OPTIMIZATION_TEST_LIBRARY to the built plugin DLL/SO")
	}
	key := "local-library-contract-key-32bytes-minimum"
	t.Setenv(roombridge.KeyEnv, key)
	var forbidden atomic.Bool
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if roombridge.Present(r.Header) {
			t.Error("proof leaked upstream")
		}
		if r.Header.Get("Authorization") != "Bearer fixture-access-token" {
			t.Error("selected source token lost")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "fixture hello") {
			t.Errorf("translated original input missing: %s", body)
		}
		if forbidden.Load() {
			w.WriteHeader(403)
			_, _ = io.WriteString(w, `{"error":{"message":"fixture forbidden"}}`)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp_fixture\",\"model\":\"gpt-6-astra\",\"status\":\"in_progress\",\"output\":[]}}\n\nevent: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"fixture success\"}\n\n")
		_, _ = io.WriteString(w, "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_fixture\",\"object\":\"response\",\"model\":\"gpt-6-astra\",\"status\":\"completed\",\"output\":[{\"id\":\"msg_fixture\",\"type\":\"message\",\"role\":\"assistant\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":\"fixture success\",\"annotations\":[]}]}],\"usage\":{\"input_tokens\":4,\"output_tokens\":2,\"total_tokens\":6}}}\n\n")
	}))
	defer upstream.Close()
	plugins := t.TempDir()
	state := t.TempDir()
	rawLibrary, err := os.ReadFile(library)
	if err != nil {
		t.Fatal(err)
	}
	pluginPath := filepath.Join(plugins, "installed-room-plugin"+pluginExtension(runtime.GOOS))
	if err = os.WriteFile(pluginPath, rawLibrary, 0600); err != nil {
		t.Fatal(err)
	}
	// JSON quoted scalars are valid YAML and safely encode Windows paths.
	quote := func(v string) string { b, _ := json.Marshal(v); return string(b) }
	yaml := fmt.Sprintf("plugins:\n  enabled: true\n  dir: %s\n  configs:\n    installed-room-plugin:\n      enabled: true\n      state_dir: %s\n      responses_url: %s\n      enabled_models: [gpt-6-astra, gpt-5.6-sol]\n", quote(plugins), quote(state), quote(upstream.URL))
	cfg, err := config.ParseConfigBytes([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	host := New()
	defer host.ShutdownAll()
	host.ApplyConfig(context.Background(), cfg)
	if !host.PluginRegistered("installed-room-plugin") {
		t.Fatal("real dynamic plugin did not register")
	}
	manager := coreauth.NewManager(nil, nil, nil)
	host.SetAuthManager(manager)
	auth := &coreauth.Auth{ID: "fixture-native.json", Provider: "codex", Prefix: "fixture-source", Status: coreauth.StatusActive, Metadata: map[string]any{"access_token": "fixture-access-token", "account_id": "fixture-account"}}
	auth.EnsureIndex()
	if _, err = manager.Register(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	invoke := func(room string, stream bool, modelChoices ...[]string) (coreexecutor.Response, error) {
		body := []byte(fmt.Sprintf(`{"model":"fixture-source/gpt-6-astra","messages":[{"role":"user","content":"fixture hello"}],"stream":%t}`, stream))
		claims := roombridge.Claims{Version: 1, RoomID: room, AccountID: "fixture-account", Prefix: auth.Prefix, AuthIndex: auth.Index, Model: "gpt-6-astra", Enabled: true, AutoDisableOn403: true, RequestID: fmt.Sprint(time.Now().UnixNano()), PolicyVersion: 1}
		if len(modelChoices) > 0 {
			claims.Version = 2
			claims.ProtectionModels = &modelChoices[0]
		}
		headers, err := roombridge.Sign([]byte(key), claims, body, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		route, ok := host.RouteModel(context.Background(), pluginapi.ModelRouteRequest{SourceFormat: "openai", RequestedModel: "fixture-source/gpt-6-astra", Body: body, Headers: headers, Stream: stream})
		if !ok || route.Target != "installed-room-plugin" {
			t.Fatalf("signed real plugin route unavailable: %+v %v", route, ok)
		}
		var selectedID, selectedIndex string
		opts := coreexecutor.Options{Stream: stream, Headers: headers, OriginalRequest: body, SourceFormat: sdktranslator.FormatOpenAI, ResponseFormat: sdktranslator.FormatOpenAI, Metadata: map[string]any{coreexecutor.SelectedAuthCallbackMetadataKey: func(v string) { selectedID = v }, coreexecutor.SelectedAuthIndexCallbackMetadataKey: func(v string) { selectedIndex = v }}}
		req := coreexecutor.Request{Model: "fixture-source/gpt-6-astra", Payload: body}
		var response coreexecutor.Response
		if stream {
			var result *coreexecutor.StreamResult
			result, err = host.ExecutePluginExecutorStream(context.Background(), route.Target, req, opts)
			if err == nil {
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						err = chunk.Err
						break
					}
					response.Payload = append(response.Payload, chunk.Payload...)
				}
			}
		} else {
			response, err = host.ExecutePluginExecutor(context.Background(), route.Target, req, opts)
		}
		if selectedID != auth.ID || selectedIndex != auth.Index {
			t.Fatal("real plugin selection trace missing")
		}
		deadline := time.Now().Add(time.Second)
		for host.OptimizationActive() != 0 && time.Now().Before(deadline) {
			runtime.Gosched()
		}
		if host.OptimizationActive() != 0 {
			t.Fatal("real plugin execution lease leaked")
		}
		return response, err
	}
	response, err := invoke("room-a", false)
	if err != nil || !strings.Contains(string(response.Payload), "fixture success") {
		t.Fatalf("nonstream real ABI: %s %v", response.Payload, err)
	}
	response, err = invoke("room-stream", true)
	if err != nil || !strings.Contains(string(response.Payload), "fixture success") {
		t.Fatalf("successful streaming real ABI: %s %v", response.Payload, err)
	}
	forbidden.Store(true)
	_, err = invoke("room-a", true)
	var status interface{ StatusCode() int }
	if !errors.As(err, &status) || status.StatusCode() != 403 || !strings.Contains(err.Error(), `"protection_models":["gpt-6-astra"]`) {
		t.Fatalf("stream protection status lost: %v", err)
	}
	before := calls.Load()
	_, err = invoke("room-a", false)
	if err == nil || !strings.Contains(err.Error(), `"protection_models":["gpt-6-astra"]`) || calls.Load() != before {
		t.Fatal("protected room reached upstream")
	}
	for _, models := range [][]string{{}, {"gpt-5.6-sol"}, {"gpt-6-astra", "gpt-5.6-sol"}} {
		encoded, _ := json.Marshal(models)
		room := "v2-" + string(encoded)
		_, err = invoke(room, true, models)
		if !errors.As(err, &status) || status.StatusCode() != 403 || !strings.Contains(err.Error(), `"protection_models":`+string(encoded)) {
			t.Fatalf("v2 ABI protection choices lost: %v", err)
		}
		prior := calls.Load()
		_, err = invoke(room, false, []string{"gpt-6-astra"})
		if err == nil || !strings.Contains(err.Error(), `"protection_models":`+string(encoded)) || calls.Load() != prior {
			t.Fatalf("v2 ABI changed first protection: %v", err)
		}
	}
	before = calls.Load()
	forbidden.Store(false)
	response, err = invoke("room-b", false)
	if err != nil || !strings.Contains(string(response.Payload), "fixture success") || calls.Load() != before+1 {
		t.Fatalf("room isolation: %s %v", response.Payload, err)
	}
	if route, ok := host.RouteModel(context.Background(), pluginapi.ModelRouteRequest{SourceFormat: "openai", RequestedModel: "gpt-6-astra", Body: []byte(`{"model":"gpt-6-astra"}`)}); ok || route.Handled {
		t.Fatal("real plugin captured unsigned model")
	}
}
