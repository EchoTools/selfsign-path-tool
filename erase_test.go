package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSecureOverwriteChangesContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	original := bytes.Repeat([]byte("PRIVATE KEY MATERIAL "), 64)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}

	if err := secureOverwriteFile(path); err != nil {
		t.Fatalf("secureOverwriteFile failed: %v", err)
	}

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(original) {
		t.Fatalf("size changed: got %d, want %d", len(after), len(original))
	}
	if bytes.Equal(after, original) {
		t.Fatal("contents unchanged after overwrite")
	}
	if bytes.Contains(after, []byte("PRIVATE KEY MATERIAL")) {
		t.Fatal("original key text still present after overwrite")
	}
}

func TestSecureDeleteRemovesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, []byte("secret"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := secureDeleteFile(path); err != nil {
		t.Fatalf("secureDeleteFile failed: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after secureDeleteFile: %v", err)
	}
}

func TestSecureDeleteMissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.pem")
	if err := secureDeleteFile(path); err != nil {
		t.Fatalf("secureDeleteFile on missing file returned %v, want nil", err)
	}
}
