package releasecontrol

import (
	"context"
	"path/filepath"
	"testing"
)

func TestOwnershipTransferWaitsForRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "refresh.lock")
	first, err := NewOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.Enter(context.Background()); err == nil {
		t.Fatal("candidate admitted refresh")
	}
	if err := first.Activate(); err != nil {
		t.Fatal(err)
	}
	release, err := first.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := first.Quiesce(ctx); err == nil {
		t.Fatal("quiesce passed while refresh active")
	}
	if _, err := first.Enter(context.Background()); err == nil {
		t.Fatal("quiescing owner admitted refresh")
	}
	if err := second.Activate(); err == nil {
		t.Fatal("second owner stole active refresh lock")
	}
	release()
	release()
	if err := first.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := second.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := second.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Activate(); err != nil {
		t.Fatal(err)
	}
	if err := first.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
}
