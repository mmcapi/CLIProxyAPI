package releasecontrol

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlRequiresSecretAndExplicitActivation(t *testing.T) {
	owner, err := NewOwner(filepath.Join(t.TempDir(), "owner.lock"))
	if err != nil {
		t.Fatal(err)
	}
	key := strings.Repeat("k", 32)
	handler := owner.Handler(key)
	for _, token := range []string{"", "Bearer wrong", key} {
		req := httptest.NewRequest(http.MethodPost, "/activate", nil)
		req.Header.Set("Authorization", token)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		if result.Code != http.StatusUnauthorized || owner.Status().Owner {
			t.Fatal("unauthorized activation")
		}
	}
	for _, action := range []string{"activate", "quiesce"} {
		req := httptest.NewRequest(http.MethodPost, "/"+action, nil)
		req.Header.Set("Authorization", "Bearer "+key)
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, req)
		if result.Code != http.StatusOK {
			t.Fatalf("%s: %d", action, result.Code)
		}
	}
	if owner.Status().Owner {
		t.Fatal("quiesce kept idle ownership")
	}
}
