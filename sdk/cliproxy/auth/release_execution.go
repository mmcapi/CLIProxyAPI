package auth

import (
	"context"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// ReleaseExecutionsActive counts raw native streams until their upstream producer
// closes its channel, even after an outer HTTP or plugin wrapper is cancelled.
func (m *Manager) ReleaseExecutionsActive() int64 { return m.releaseExecutions.Load() }

func (m *Manager) executeReleaseStream(ctx context.Context, executor ProviderExecutor, auth *Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	if m.credentialGate() == nil {
		return executor.ExecuteStream(ctx, auth, req, opts)
	}
	m.releaseExecutions.Add(1)
	result, err := executor.ExecuteStream(ctx, auth, req, opts)
	if result == nil || result.Chunks == nil {
		m.releaseExecutions.Add(-1)
		return result, err
	}
	raw := result.Chunks
	out := make(chan coreexecutor.StreamChunk)
	copyResult := *result
	copyResult.Chunks = out
	go func() {
		defer close(out)
		defer m.releaseExecutions.Add(-1)
		for chunk := range raw {
			if err != nil {
				continue
			}
			select {
			case out <- chunk:
			case <-ctx.Done():
			}
		}
	}()
	return &copyResult, err
}
