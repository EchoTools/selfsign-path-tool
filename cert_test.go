package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// assertNoKeyMaterial fails if any file under dir is a .key file or holds a PEM private key.
func assertNoKeyMaterial(t *testing.T, dir string) {
	t.Helper()
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, ".key") {
			t.Errorf("key file left on disk: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Errorf("private key material found in: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", dir, err)
	}
}

func TestCreateCertificateWritesNoKeyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	if _, err := createSelfSignedCertificate("NoKeyTest"); err != nil {
		t.Fatalf("createSelfSignedCertificate failed: %v", err)
	}
	assertNoKeyMaterial(t, home)
}

func TestSelfSignedCertValidityIsTenYears(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("APPDATA", filepath.Join(home, "AppData", "Roaming"))

	cert, err := createSelfSignedCertificate("ValidityTest")
	if err != nil {
		t.Fatalf("createSelfSignedCertificate failed: %v", err)
	}

	want := time.Now().AddDate(10, 0, 0)
	diff := cert.Cert.NotAfter.Sub(want)
	if diff < 0 {
		diff = -diff
	}
	if diff > time.Minute {
		t.Errorf("NotAfter = %s, want about %s (10 years from now)", cert.Cert.NotAfter, want)
	}
}
