package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/roombridge"
)

func TestOptimizationNeverFallsBackToNative(t *testing.T) {
	for _, tc := range []struct {
		name string
		host *handlerModelRouterTestHost
	}{
		{name: "absent"},
		{name: "disabled", host: &handlerModelRouterTestHost{}},
		{name: "declined", host: &handlerModelRouterTestHost{hasRouters: true}},
		{name: "native-provider", host: &handlerModelRouterTestHost{hasRouters: true, route: func(context.Context, pluginapi.ModelRouteRequest, string) (pluginapi.ModelRouteResponse, bool) {
			return pluginapi.ModelRouteResponse{Handled: true, TargetKind: pluginapi.ModelRouteTargetProvider, Target: "codex"}, true
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &BaseAPIHandler{}
			if tc.host != nil {
				h.SetPluginHost(tc.host)
			}
			headers := make(http.Header)
			headers.Set(roombridge.ClaimsHeader, "proof")
			opts := modelExecutionOptions{Headers: headers}
			decision := h.applyModelRouter(context.Background(), "openai", "source/gpt-6-astra", []byte(`{}`), false, opts)
			if decision.Error == nil || decision.Error.StatusCode != 503 {
				t.Fatalf("signed route fell through: %+v", decision)
			}
			if _, _, err := h.providersForExecution("source/gpt-6-astra", "source/gpt-6-astra", false, decision, opts); err == nil {
				t.Fatal("native provider selected")
			}
			if err := validateNativeInteractionsExecution("openai", opts, decision); err == nil {
				t.Fatal("execution ignored route error")
			}
			unsigned := h.applyModelRouter(context.Background(), "openai", "model", nil, false, modelExecutionOptions{})
			if unsigned.Error != nil {
				t.Fatal("unsigned execution changed")
			}
		})
	}
}
