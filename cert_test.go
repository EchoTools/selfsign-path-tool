package main

import (
	"path/filepath"
	"testing"
	"time"
)

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
