package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildTool builds the real binary into a temporary directory.
func buildTool(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "selfsign-path-tool")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}
	return bin
}

// toolEnv points the certificate directory and audit log at a temporary home.
func toolEnv(home string) []string {
	return append(os.Environ(),
		"HOME="+home,
		"USERPROFILE="+home,
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
	)
}

// runTool runs the binary with the given arguments and returns its combined output.
func runTool(t *testing.T, bin, home string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Env = toolEnv(home)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// readAuditRecords parses every line of the audit log under home.
func readAuditRecords(t *testing.T, home string) []auditRecord {
	t.Helper()
	path := filepath.Join(home, ".local", "share", "selfsign-path-tool", "certificates", auditFileName)
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("audit log missing at %s: %v", path, err)
	}
	defer f.Close()

	var records []auditRecord
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var r auditRecord
		if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
			t.Fatalf("audit line is not JSON: %v\n%s", err, scanner.Text())
		}
		records = append(records, r)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return records
}

func TestSidecarOnlyWritesAuditRecord(t *testing.T) {
	bin := buildTool(t)
	home := t.TempDir()
	target := filepath.Join(t.TempDir(), "app.exe")
	if err := os.WriteFile(target, []byte("MZ placeholder"), 0644); err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(target)

	if out, err := runTool(t, bin, home, "--sidecar-only", target); err != nil {
		t.Fatalf("--sidecar-only failed: %v\n%s", err, out)
	}

	if _, err := os.Stat(target + ".sig"); err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	after, _ := os.ReadFile(target)
	if string(after) != string(original) {
		t.Error("--sidecar-only modified the target file")
	}

	records := readAuditRecords(t, home)
	found := false
	for _, r := range records {
		if r.Op == "sign" && r.Mode == "sidecar" && r.Outcome == "ok" && r.File == target {
			found = true
		}
	}
	if !found {
		t.Fatalf("no sign/sidecar/ok audit record for %s in %d records", target, len(records))
	}
}

func TestAuthenticodeSignStatusClear(t *testing.T) {
	if _, err := exec.LookPath("osslsigncode"); err != nil {
		t.Skip("osslsigncode not on PATH")
	}
	bin := buildTool(t)
	home := t.TempDir()

	// Build a real PE file to sign.
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(src, "app.exe")
	build := exec.Command("go", "build", "-o", target, "main.go")
	build.Dir = src
	build.Env = append(os.Environ(), "GOOS=windows", "GOARCH=amd64", "CGO_ENABLED=0", "GOWORK=off", "GOFLAGS=")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building Windows PE fixture failed: %v\n%s", err, out)
	}

	if out, err := runTool(t, bin, home, target); err != nil {
		t.Fatalf("sign failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(target + ".sig"); err == nil {
		t.Error("default signing wrote a sidecar file")
	}
	assertNoKeyMaterial(t, home)

	status, err := runTool(t, bin, home, "--status", target)
	if err != nil {
		t.Fatalf("--status failed: %v\n%s", err, status)
	}
	if !strings.Contains(status, "Signer: CN=LocalSign-SelfSigned") {
		t.Errorf("status does not show the embedded signer:\n%s", status)
	}

	if out, err := runTool(t, bin, home, "--clear", target); err != nil {
		t.Fatalf("--clear failed: %v\n%s", err, out)
	}
	status, _ = runTool(t, bin, home, "--status", target)
	if !strings.Contains(status, "Status: NotSigned") {
		t.Errorf("file still signed after --clear:\n%s", status)
	}

	ok := map[string]bool{}
	for _, r := range readAuditRecords(t, home) {
		if r.Outcome != "ok" {
			continue
		}
		if r.Op == "sign" && r.Mode != "authenticode" {
			t.Errorf("sign record has mode %q, want authenticode", r.Mode)
		}
		ok[r.Op] = true
	}
	for _, op := range []string{"sign", "status", "clear"} {
		if !ok[op] {
			t.Errorf("no successful %q audit record", op)
		}
	}
}
