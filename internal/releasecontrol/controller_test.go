package releasecontrol

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestControllerDrainsBeforeOwnershipTransfer(t *testing.T) {
	owner, _ := NewOwner(filepath.Join(t.TempDir(), "owner.lock"))
	key := strings.Repeat("k", 32)
	var plugins atomic.Int64
	var reloads atomic.Int64
	c := NewController(owner, key, func() error {
		reloads.Add(1)
		if _, err := owner.Enter(context.Background()); err == nil {
			t.Error("reload admitted mutation")
		}
		return nil
	}, plugins.Load, nil)
	entered := make(chan struct{})
	finish := make(chan struct{})
	handler := c.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-finish; w.WriteHeader(200) }))
	control := func(action string) int {
		req := httptest.NewRequest("POST", ControlPrefix+action, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response.Code
	}
	req := httptest.NewRequest("POST", "/v1/responses", nil)
	before := httptest.NewRecorder()
	handler.ServeHTTP(before, req)
	if before.Code != 503 {
		t.Fatal("standby accepted inference")
	}
	if control("activate") != 200 || reloads.Load() != 1 {
		t.Fatal("activation failed")
	}
	done := make(chan struct{})
	go func() { defer close(done); handler.ServeHTTP(httptest.NewRecorder(), req) }()
	<-entered
	if control("quiesce") != 200 || owner.Status().Owner || c.Status().SafeToStop {
		t.Fatal("ownership transfer failed or declared active stream safe to stop")
	}
	after := httptest.NewRecorder()
	handler.ServeHTTP(after, req)
	if after.Code != 503 {
		t.Fatal("draining accepted inference")
	}
	plugins.Store(1)
	close(finish)
	<-done
	if control("quiesce") != 200 || c.Status().SafeToStop {
		t.Fatal("declared detached plugin safe to stop")
	}
	plugins.Store(0)
	if control("quiesce") != 200 || !c.Status().SafeToStop {
		t.Fatal("did not complete drain")
	}
	if allowedManagement("GET", "/v0/management/codex-auth-url") || allowedManagement("POST", "/v0/management/auth-files/refresh") {
		t.Fatal("asynchronous legacy endpoint allowed")
	}
	if !allowedManagement("GET", "/v0/management/plugins/oai-basispoints-cpa/status") || allowedManagement("POST", "/v0/management/plugins/oai-basispoints-cpa/status") {
		t.Fatal("optimization status must be read only")
	}
	for _, path := range []string{"/v8/management/oauth/auth-url", "/v8/management/credentials/refresh", "/v8/management/config"} {
		response := httptest.NewRecorder()
		c.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("v8 management bypassed release control") })).ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusForbidden {
			t.Fatalf("v8 management status: %d", response.Code)
		}
	}
}

func TestActivateReloadFailureReleasesOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner.lock")
	first, _ := NewOwner(path)
	second, _ := NewOwner(path)
	if err := first.ActivateWith(func() error { return errors.New("read failed") }); err == nil {
		t.Fatal("reload failure ignored")
	}
	if first.Status().Accepting {
		t.Fatal("failed reload admits writes")
	}
	if err := second.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := second.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestNativeUpstreamPreventsSafeStop(t *testing.T) {
	owner, _ := NewOwner(filepath.Join(t.TempDir(), "owner.lock"))
	var upstream atomic.Int64
	upstream.Store(1)
	controller := NewController(owner, strings.Repeat("k", 32), nil, nil, upstream.Load)
	if controller.Status().SafeToStop {
		t.Fatal("native cleanup still active")
	}
	upstream.Store(0)
	if !controller.Status().SafeToStop {
		t.Fatal("completed native cleanup still blocks")
	}
}
