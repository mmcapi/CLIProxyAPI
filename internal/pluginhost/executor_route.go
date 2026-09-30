package pluginhost

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/roombridge"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

// executorPluginReady reports whether the named plugin can actually execute a
// request right now: it must declare an executor capability AND resolve a
// non-empty provider identifier (the same requirement enforced by
// executorAdapterForPlugin at execution time), allow static execution without
// selected auth, and declare formats compatible with the current request.
// Routing pre-checks use this so that targets which would fail at execution are
// treated as unhandled and fall through to lower-priority routers instead of
// returning handled then 500ing.
func (h *Host) executorPluginReady(pluginID string, routeReq pluginapi.ModelRouteRequest) bool {
	if h == nil {
		return false
	}
	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		return false
	}
	for _, record := range h.activeRecords() {
		if record.id != pluginID || h.isPluginFused(record.id) {
			continue
		}
		executor := record.plugin.Capabilities.Executor
		if executor == nil {
			return false
		}
		if !executorScopeAllowsStaticModels(record.plugin.Capabilities) {
			return false
		}
		provider, okProvider := h.executorProvider(record, executor)
		if !okProvider {
			return false
		}
		adapter := newExecutorAdapterRegistration(h, record, provider, executor).adapter
		return adapter.supportsExecutorFormats(
			coreexecutor.Request{Model: routeReq.RequestedModel, Payload: routeReq.Body},
			coreexecutor.Options{
				Stream:          routeReq.Stream,
				OriginalRequest: routeReq.Body,
				SourceFormat:    sdktranslator.FromString(routeReq.SourceFormat),
				ResponseFormat:  sdktranslator.FromString(routeReq.SourceFormat),
				Headers:         cloneHeader(routeReq.Headers),
				Query:           cloneValues(routeReq.Query),
				Metadata:        cloneInterceptorMetadata(routeReq.Metadata),
			},
		)
	}
	return false
}

func (a *executorAdapter) supportsExecutorFormats(req coreexecutor.Request, opts coreexecutor.Options) bool {
	if a == nil {
		return false
	}
	inputRequested := executorInputFormat(req, opts)
	requestedFormat := executorRequestedFormat(req, opts)
	inputFormat, errInput := a.selectExecutorInputFormat(inputRequested)
	if errInput != nil {
		return false
	}
	_, errOutput := a.selectExecutorOutputFormat(requestedFormat, inputFormat)
	return errOutput == nil
}

// PluginExecutorRequestToFormat reports the executor input format selected for a direct plugin executor route.
func (h *Host) PluginExecutorRequestToFormat(pluginID string, req coreexecutor.Request, opts coreexecutor.Options) sdktranslator.Format {
	adapter, errAdapter := h.executorAdapterForPlugin(pluginID)
	if errAdapter != nil {
		return ""
	}
	return adapter.RequestToFormat(req, opts)
}

// ExecutePluginExecutor executes a request with the named plugin executor without changing the requested model.
func (h *Host) ExecutePluginExecutor(ctx context.Context, pluginID string, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	auth, errProof := h.optimizationExecutionAuth(pluginID, opts, time.Now())
	if errProof != nil {
		return coreexecutor.Response{}, errProof
	}
	if auth != nil {
		ctx = context.WithValue(ctx, optimizationExecutionKey{}, true)
	}
	adapter, errAdapter := h.executorAdapterForPlugin(pluginID)
	if errAdapter != nil {
		return coreexecutor.Response{}, errAdapter
	}
	return adapter.Execute(ctx, auth, req, opts)
}

// ExecutePluginExecutorStream executes a streaming request with the named plugin executor without changing the requested model.
func (h *Host) ExecutePluginExecutorStream(ctx context.Context, pluginID string, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	if opts.Metadata == nil {
		opts.Metadata = make(map[string]any)
	}
	auth, errProof := h.optimizationExecutionAuth(pluginID, opts, time.Now())
	if errProof != nil {
		return nil, errProof
	}
	if auth != nil {
		ctx = context.WithValue(ctx, optimizationExecutionKey{}, true)
	}
	adapter, errAdapter := h.executorAdapterForPlugin(pluginID)
	if errAdapter != nil {
		return nil, errAdapter
	}
	return adapter.ExecuteStream(ctx, auth, req, opts)
}

// optimizationExecutionAuth only grants signed internal requests access to native
// credential material. It never refreshes credentials or falls back to another auth.
func (h *Host) optimizationExecutionAuth(pluginID string, opts coreexecutor.Options, now time.Time) (*coreauth.Auth, error) {
	if !roombridge.Present(opts.Headers) {
		return nil, nil
	}
	invalid := &coreauth.Error{HTTPStatus: 403, Message: "optimization execution denied"}
	if h == nil {
		return nil, invalid
	}
	allowed := false
	for _, record := range h.activeRecords() {
		if record.id == pluginID && record.meta.Name == "oai-basispoints-cpa" && !h.isPluginFused(record.id) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, invalid
	}
	claims, err := roombridge.Verify([]byte(os.Getenv(roombridge.KeyEnv)), opts.Headers, opts.OriginalRequest, now)
	if err != nil || !claims.Enabled {
		return nil, invalid
	}
	manager := h.currentAuthManager()
	if manager == nil {
		return nil, invalid
	}
	var selected *coreauth.Auth
	for _, candidate := range manager.List() {
		if candidate == nil || candidate.Provider != "codex" || candidate.Index != claims.AuthIndex || candidate.Prefix != claims.Prefix {
			continue
		}
		if selected != nil {
			return nil, invalid
		}
		selected = candidate
	}
	if selected == nil || selected.ID == "" || selected.Disabled || selected.Unavailable || selected.Status == coreauth.StatusDisabled || selected.Status == coreauth.StatusError || selected.Status == coreauth.StatusPending || selected.NextRetryAfter.After(now) {
		return nil, invalid
	}
	for _, model := range []string{claims.Model, claims.Prefix + "/" + claims.Model} {
		if state := selected.ModelStates[model]; state != nil && (state.Unavailable || state.Status == coreauth.StatusDisabled || state.Status == coreauth.StatusError || state.NextRetryAfter.After(now)) {
			return nil, invalid
		}
	}
	if opts.Metadata != nil {
		opts.Metadata["mmc_optimization_auth_index"] = selected.Index
		opts.Metadata[coreexecutor.SelectedAuthMetadataKey] = selected.ID
		opts.Metadata[coreexecutor.SelectedAuthIndexMetadataKey] = selected.Index
		if callback, ok := opts.Metadata[coreexecutor.SelectedAuthCallbackMetadataKey].(func(string)); ok && callback != nil {
			callback(selected.ID)
		}
		if callback, ok := opts.Metadata[coreexecutor.SelectedAuthIndexCallbackMetadataKey].(func(string)); ok && callback != nil {
			callback(selected.Index)
		}
	}
	return selected, nil
}

// CountPluginExecutor executes a count-tokens request with the named plugin executor without changing the requested model.
func (h *Host) CountPluginExecutor(ctx context.Context, pluginID string, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	if roombridge.Present(opts.Headers) {
		return coreexecutor.Response{}, &coreauth.Error{HTTPStatus: 400, Message: "optimization proof is not supported for token counting"}
	}
	adapter, errAdapter := h.executorAdapterForPlugin(pluginID)
	if errAdapter != nil {
		return coreexecutor.Response{}, errAdapter
	}
	return adapter.CountTokens(ctx, (*coreauth.Auth)(nil), req, opts)
}

func (h *Host) executorAdapterForPlugin(pluginID string) (*executorAdapter, error) {
	if h == nil {
		return nil, fmt.Errorf("plugin host is unavailable")
	}
	pluginID = strings.TrimSpace(pluginID)
	if pluginID == "" {
		return nil, fmt.Errorf("target executor plugin id is required")
	}
	for _, record := range h.activeRecords() {
		if record.id != pluginID {
			continue
		}
		if h.isPluginFused(record.id) {
			return nil, fmt.Errorf("plugin executor %s is unavailable", pluginID)
		}
		executor := record.plugin.Capabilities.Executor
		if executor == nil {
			return nil, fmt.Errorf("plugin %s does not declare an executor", pluginID)
		}
		provider, okProvider := h.executorProvider(record, executor)
		if !okProvider {
			return nil, fmt.Errorf("plugin executor %s has no provider identifier", pluginID)
		}
		registration := newExecutorAdapterRegistration(h, record, provider, executor)
		return registration.adapter, nil
	}
	return nil, fmt.Errorf("plugin executor %s not found", pluginID)
}
