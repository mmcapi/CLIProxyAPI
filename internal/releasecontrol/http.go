package releasecontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Handler serves refresh-only lifecycle control beneath the mounted path. Mount
// behind the internal listener; this is not inference-request drain accounting.
// An empty/short key fails closed instead of enabling unauthenticated control.
func (o *Owner) Handler(token string) http.Handler {
	expected := sha256.Sum256([]byte(token))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		supplied := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		actual := sha256.Sum256([]byte(supplied))
		if len(token) < 32 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.URL.Path == "/status" && r.Method == http.MethodGet:
		case r.URL.Path == "/activate" && r.Method == http.MethodPost:
			if err := o.Activate(); err != nil {
				http.Error(w, "refresh ownership unavailable", http.StatusConflict)
				return
			}
		case r.URL.Path == "/quiesce" && r.Method == http.MethodPost:
			ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
			defer cancel()
			if err := o.Quiesce(ctx); err != nil {
				http.Error(w, "refresh ownership remains retained; retry quiesce", http.StatusConflict)
				return
			}
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(o.Status())
	})
}
