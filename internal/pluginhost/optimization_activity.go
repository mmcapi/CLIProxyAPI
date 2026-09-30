package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

type optimizationExecutionKey struct{}
type optimizationLease struct {
	ctx      context.Context
	pluginID string
	instance *hostCallbackInstance
}
type optimizationActivities struct {
	mu     sync.Mutex
	leases map[string]optimizationLease
}

// OptimizationActive counts plugin work until its actual upstream cleanup acknowledgement.
// Lost plugin acknowledgements deliberately prevent an unsafe drain decision.
func (h *Host) OptimizationActive() int {
	if h == nil {
		return 0
	}
	h.optimizationActivity.mu.Lock()
	defer h.optimizationActivity.mu.Unlock()
	return len(h.optimizationActivity.leases)
}

func (a *rpcPluginAdapter) reserveOptimization(ctx context.Context, id string) {
	if active, _ := ctx.Value(optimizationExecutionKey{}).(bool); !active {
		return
	}
	h := a.host
	h.optimizationActivity.mu.Lock()
	defer h.optimizationActivity.mu.Unlock()
	if h.optimizationActivity.leases == nil {
		h.optimizationActivity.leases = make(map[string]optimizationLease)
	}
	h.optimizationActivity.leases[id] = optimizationLease{ctx: ctx, pluginID: a.id, instance: a.instance}
}

func (h *Host) callOptimizationActivity(ctx context.Context, request []byte, closeLease bool) ([]byte, error) {
	var req struct {
		HostCallbackID string `json:"host_callback_id"`
	}
	if json.Unmarshal(request, &req) != nil || req.HostCallbackID == "" {
		return nil, fmt.Errorf("invalid optimization callback")
	}
	h.optimizationActivity.mu.Lock()
	defer h.optimizationActivity.mu.Unlock()
	lease, ok := h.optimizationActivity.leases[req.HostCallbackID]
	if !ok || hostCallbackPluginIDFromContext(ctx) != lease.pluginID || hostCallbackInstanceFromContext(ctx) != lease.instance {
		return nil, fmt.Errorf("unknown optimization execution")
	}
	if closeLease {
		delete(h.optimizationActivity.leases, req.HostCallbackID)
		return marshalRPCResult(rpcEmptyResponse{})
	}
	return marshalRPCResult(struct {
		Cancelled bool `json:"cancelled"`
	}{Cancelled: lease.ctx.Err() != nil})
}
