package auth

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/releasecontrol"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFileStoreRejectsNonOwnerWrites(t *testing.T) {
	dir := t.TempDir()
	owner, _ := releasecontrol.NewOwner(filepath.Join(dir, "refresh.lock"))
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	store.SetCredentialWriteGate(owner)
	auth := &coreauth.Auth{ID: "account.json", FileName: "account.json", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "new"}}
	if _, err := store.Save(context.Background(), auth); err == nil {
		t.Fatal("standby wrote credentials")
	}
	if err := owner.Activate(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Save(context.Background(), auth); err != nil {
		t.Fatal(err)
	}
	if err := owner.Quiesce(context.Background()); err != nil {
		t.Fatal(err)
	}
	auth.Metadata["access_token"] = "stale"
	if _, err := store.Save(context.Background(), auth); err == nil {
		t.Fatal("old instance overwrote credentials")
	}
	if err := store.Delete(context.Background(), "account.json"); err == nil {
		t.Fatal("old instance deleted credentials")
	}
	if _, err := os.Stat(filepath.Join(dir, "account.json")); err != nil {
		t.Fatal(err)
	}
}
