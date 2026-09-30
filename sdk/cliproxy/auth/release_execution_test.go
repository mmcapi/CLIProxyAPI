package auth

import (
	"context"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"testing"
)

type delayedReleaseExecutor struct {
	countingRefreshExecutor
	raw chan coreexecutor.StreamChunk
}

func (e *delayedReleaseExecutor) ExecuteStream(context.Context, *Auth, coreexecutor.Request, coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	return &coreexecutor.StreamResult{Chunks: e.raw}, nil
}

func TestReleaseTracksRawUpstreamAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewManager(nil, nil, nil)
	manager.SetRefreshGate(&observedRefreshGate{})
	executor := &delayedReleaseExecutor{raw: make(chan coreexecutor.StreamChunk)}
	result, err := manager.executeReleaseStream(ctx, executor, nil, coreexecutor.Request{}, coreexecutor.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if manager.ReleaseExecutionsActive() != 1 {
		t.Fatal("raw executor not tracked")
	}
	cancel()
	executor.raw <- coreexecutor.StreamChunk{Payload: []byte("late upstream cleanup")}
	if manager.ReleaseExecutionsActive() != 1 {
		t.Fatal("HTTP cancellation falsely completed raw upstream")
	}
	close(executor.raw)
	for range result.Chunks {
	}
	if manager.ReleaseExecutionsActive() != 0 {
		t.Fatal("closed upstream not released")
	}
}
