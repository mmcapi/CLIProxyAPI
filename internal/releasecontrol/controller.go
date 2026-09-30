package releasecontrol

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ControlPrefix = "/__mmc_release/"

type Controller struct {
	mu             sync.Mutex
	operations     sync.Mutex
	owner          *Owner
	token          string
	reload         func() error
	pluginActive   func() int64
	upstreamActive func() int64
	admitting      bool
	requests       int
}

type LifecycleStatus struct {
	Refresh        Status `json:"refresh"`
	Admitting      bool   `json:"admitting"`
	HTTPActive     int    `json:"http_active"`
	PluginActive   int64  `json:"plugin_active"`
	UpstreamActive int64  `json:"upstream_active"`
	SafeToStop     bool   `json:"safe_to_stop"`
}

func NewController(owner *Owner, token string, reload func() error, pluginActive func() int64, upstreamActive func() int64) *Controller {
	return &Controller{owner: owner, token: token, reload: reload, pluginActive: pluginActive, upstreamActive: upstreamActive}
}

func (c *Controller) Status() LifecycleStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := LifecycleStatus{Refresh: c.owner.Status(), Admitting: c.admitting, HTTPActive: c.requests}
	if c.pluginActive != nil {
		status.PluginActive = c.pluginActive()
	}
	if c.upstreamActive != nil {
		status.UpstreamActive = c.upstreamActive()
	}
	status.SafeToStop = !status.Admitting && status.HTTPActive == 0 && status.PluginActive == 0 && status.UpstreamActive == 0 && !status.Refresh.Owner && status.Refresh.InFlight == 0
	return status
}

func (c *Controller) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, ControlPrefix) {
			c.control(w, r)
			return
		}
		management := strings.HasPrefix(r.URL.Path, "/v0/") || strings.HasPrefix(r.URL.Path, "/v8/management")
		if management && !allowedManagement(r.Method, r.URL.Path) {
			http.Error(w, "endpoint unavailable during managed releases", http.StatusForbidden)
			return
		}
		c.mu.Lock()
		if !c.admitting {
			c.mu.Unlock()
			w.Header().Set("X-MMC-Admission-Rejected", "true")
			http.Error(w, "instance is not admitting requests", http.StatusServiceUnavailable)
			return
		}
		c.requests++
		c.mu.Unlock()
		defer func() { c.mu.Lock(); c.requests--; c.mu.Unlock() }()
		if management {
			ctx, release, err := c.owner.EnterContext(r.Context())
			if err != nil {
				http.Error(w, "credential ownership unavailable", http.StatusServiceUnavailable)
				return
			}
			defer release()
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func allowedManagement(method, path string) bool {
	switch method + " " + path {
	case "GET /v0/management/auth-files", "GET /v0/management/auth-files/models",
		"POST /v0/management/auth-files", "DELETE /v0/management/auth-files",
		"PATCH /v0/management/auth-files/status", "PATCH /v0/management/auth-files/fields",
		"POST /v0/management/api-call",
		"GET /v0/management/plugins/oai-basispoints-cpa/status":
		return true
	}
	return false
}

func (c *Controller) control(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet && r.URL.Path == ControlPrefix+"health" {
		w.WriteHeader(http.StatusOK)
		return
	}
	expected := sha256.Sum256([]byte(c.token))
	actual := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
	if len(c.token) < 32 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || subtle.ConstantTimeCompare(expected[:], actual[:]) != 1 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	c.operations.Lock()
	defer c.operations.Unlock()
	switch {
	case r.Method == http.MethodGet && r.URL.Path == ControlPrefix+"status":
	case r.Method == http.MethodPost && r.URL.Path == ControlPrefix+"activate":
		before := c.Status()
		if !before.Admitting && (before.HTTPActive != 0 || before.PluginActive != 0 || before.UpstreamActive != 0) {
			http.Error(w, "prior executions must finish before reactivation", http.StatusConflict)
			return
		}
		if err := c.owner.ActivateWith(c.reload); err != nil {
			http.Error(w, "activation unavailable", http.StatusConflict)
			return
		}
		c.mu.Lock()
		c.admitting = true
		c.mu.Unlock()
	case r.Method == http.MethodPost && (r.URL.Path == ControlPrefix+"drain" || r.URL.Path == ControlPrefix+"quiesce"):
		c.mu.Lock()
		c.admitting = false
		c.mu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := c.owner.Quiesce(ctx); err != nil {
			http.Error(w, "credential writes draining; retry quiesce", http.StatusConflict)
			return
		}
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c.Status())
}
