package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SignatureStatus represents the status of a file's signature
type SignatureStatus struct {
	Status               string
	SignerCertificate    string
	TimestampCertificate string
	IsSelfSigned         bool
}

// sidecarSuffix names the legacy text signature file written by --sidecar-only.
const sidecarSuffix = ".sig"

// signFile signs a file with the given certificate. It embeds an Authenticode
// signature via osslsigncode, or writes a sidecar file when --sidecar-only is set.
func signFile(filename string, cert *Certificate) error {
	rec := startAudit("sign", filename)
	rec.Cert = cert.Cert.Subject.String()
	start := time.Now()

	var err error
	if *flagSidecarOnly {
		rec.Mode = "sidecar"
		err = writeSidecar(filename, cert)
	} else {
		rec.Mode = "authenticode"
		err = signAuthenticode(filename, cert)
	}

	rec.finish(err, start)
	return err
}

// getFileSignatureStatus checks the signature status of a file
func getFileSignatureStatus(filename string) (*SignatureStatus, error) {
	rec := startAudit("status", filename)
	start := time.Now()

	status, err := signatureStatus(filename)
	if status != nil {
		rec.Mode = statusMode(status)
		rec.Cert = status.SignerCertificate
	}

	rec.finish(err, start)
	return status, err
}

// removeSelfSignedSignature removes self-signed signatures from a file
func removeSelfSignedSignature(filename string) (bool, error) {
	rec := startAudit("clear", filename)
	start := time.Now()

	removed, err := clearSelfSigned(filename)

	rec.finish(err, start)
	return removed, err
}

// installCertificateToStore installs the certificate to the system trust store
func installCertificateToStore(cert interface{}) error {
	return installCertificateToStorePlatform(cert)
}

// signAuthenticode embeds an Authenticode signature in filename using osslsigncode.
// The signed copy is written beside the original and renamed over it on success,
// so a failed run leaves the original untouched.
func signAuthenticode(filename string, cert *Certificate) error {
	if _, err := osslsigncodeTool(); err != nil {
		return err
	}

	workDir, err := os.MkdirTemp(getCertificateDirectory(), "sign-work-")
	if err != nil {
		return fmt.Errorf("failed to create work directory: %w", err)
	}
	defer os.RemoveAll(workDir)

	certPath := filepath.Join(workDir, "cert.pem")
	keyPath := filepath.Join(workDir, "key.pem")
	if err := writePEMFiles(certPath, keyPath, cert); err != nil {
		return err
	}

	tmpOut := filepath.Join(filepath.Dir(filename), "."+filepath.Base(filename)+".signing")
	out, err := runOsslsigncode("sign",
		"-certs", certPath, "-key", keyPath,
		"-n", cert.Subject, "-h", "sha256",
		"-in", filename, "-out", tmpOut)
	if err != nil {
		os.Remove(tmpOut)
		return fmt.Errorf("osslsigncode sign failed: %w: %s", err, strings.TrimSpace(out))
	}

	if err := os.Rename(tmpOut, filename); err != nil {
		os.Remove(tmpOut)
		return fmt.Errorf("failed to replace %s with signed copy: %w", filename, err)
	}
	return nil
}

// writePEMFiles writes the certificate and private key in the PEM form osslsigncode reads.
func writePEMFiles(certPath, keyPath string, cert *Certificate) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Cert.Raw})
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		return fmt.Errorf("failed to write certificate for signing: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key for signing: %w", err)
	}
	return nil
}

// writeSidecar writes the legacy text signature file used by --sidecar-only.
func writeSidecar(filename string, cert *Certificate) error {
	subject := cert.Cert.Subject.String()
	selfSigned := subject == cert.Cert.Issuer.String()
	content := fmt.Sprintf("SIGNED_BY=%s\nTIMESTAMP=%s\nCERT_SUBJECT=%s\nSELF_SIGNED=%t\n",
		cert.Subject,
		time.Now().Format(time.RFC3339),
		subject,
		selfSigned)

	if err := os.WriteFile(filename+sidecarSuffix, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to create signature file: %w", err)
	}
	return nil
}

// statusMode names the signature mechanism a status result came from, for the audit log.
func statusMode(status *SignatureStatus) string {
	switch {
	case status.Status == "Sidecar":
		return "sidecar"
	case status.Status == "NotSigned":
		return "none"
	default:
		return "authenticode"
	}
}

// signatureStatus reports the embedded Authenticode signature if there is one,
// otherwise the sidecar file if there is one.
func signatureStatus(filename string) (*SignatureStatus, error) {
	toolErr := osslsigncodeAvailable()

	if toolErr == nil {
		emb, err := embeddedStatus(filename)
		if err != nil {
			return nil, err
		}
		if emb.Status != "NotSigned" {
			return emb, nil
		}
	}

	side, err := sidecarStatus(filename)
	if err != nil {
		return nil, err
	}
	if side.Status == "NotSigned" && toolErr != nil {
		return nil, fmt.Errorf("cannot check for an Authenticode signature: %w", toolErr)
	}
	return side, nil
}

// embeddedStatus reads the Authenticode signature with osslsigncode verify.
func embeddedStatus(filename string) (*SignatureStatus, error) {
	out, err := runOsslsigncode("verify", "-verbose", "-in", filename)
	if strings.Contains(out, "No signature found") {
		return &SignatureStatus{Status: "NotSigned"}, nil
	}
	if strings.Contains(out, "Unable to open") || strings.Contains(out, "Unable to read") {
		return nil, fmt.Errorf("osslsigncode could not read %s: %s", filename, strings.TrimSpace(out))
	}

	signer, issuer := signerNames(out)
	status := &SignatureStatus{
		SignerCertificate: signer,
		IsSelfSigned:      signer != "" && signer == issuer,
	}

	switch {
	case err == nil:
		status.Status = "Valid"
	case digestsMatch(out) && strings.Contains(out, "self-signed certificate"):
		// Digest is intact; only trust-chain validation fails, as expected for a self-signed cert.
		status.Status = "Signed (self-signed, not trusted)"
	default:
		status.Status = "Invalid"
	}
	return status, nil
}

// signerNames returns the Subject and Issuer of the first signer certificate in
// osslsigncode's verbose output.
func signerNames(out string) (subject, issuer string) {
	inSigner := false
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Signer's certificate:") {
			inSigner = true
			continue
		}
		if !inSigner {
			continue
		}
		if subject == "" && strings.HasPrefix(trimmed, "Subject:") {
			subject = strings.TrimSpace(strings.TrimPrefix(trimmed, "Subject:"))
		} else if issuer == "" && strings.HasPrefix(trimmed, "Issuer") {
			// osslsigncode prints "Issuer : CN=..." with a space before the colon.
			rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "Issuer"))
			issuer = strings.TrimSpace(strings.TrimPrefix(rest, ":"))
		}
		if subject != "" && issuer != "" {
			break
		}
	}
	return subject, issuer
}

// digestsMatch reports whether osslsigncode's calculated and stored message digests are equal.
func digestsMatch(out string) bool {
	current, calculated := "", ""
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Current message digest") {
			current = digestValue(trimmed)
		} else if strings.HasPrefix(trimmed, "Calculated message digest") {
			calculated = digestValue(trimmed)
		}
	}
	return current != "" && current == calculated
}

// digestValue returns the value after the colon of a "... digest : VALUE" line.
func digestValue(line string) string {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(line[idx+1:]))
}

// sidecarStatus reads the legacy sidecar signature file.
func sidecarStatus(filename string) (*SignatureStatus, error) {
	data, err := os.ReadFile(filename + sidecarSuffix)
	if os.IsNotExist(err) {
		return &SignatureStatus{Status: "NotSigned"}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	status := &SignatureStatus{Status: "Sidecar"}
	legacy := true
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "SIGNED_BY="):
			status.SignerCertificate = strings.TrimPrefix(line, "SIGNED_BY=")
		case strings.HasPrefix(line, "SELF_SIGNED="):
			legacy = false
			status.IsSelfSigned = strings.TrimPrefix(line, "SELF_SIGNED=") == "true"
		}
	}
	// Sidecars written before SELF_SIGNED existed carry no flag; fall back to the old name check.
	if legacy {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CERT_SUBJECT=") {
				status.IsSelfSigned = strings.Contains(line, "LocalSign")
			}
		}
	}
	return status, nil
}

// clearSelfSigned removes the embedded Authenticode signature and the sidecar file
// when each is self-signed. It reports whether anything was removed.
func clearSelfSigned(filename string) (bool, error) {
	removed := false

	if err := osslsigncodeAvailable(); err == nil {
		emb, err := embeddedStatus(filename)
		if err != nil {
			return false, err
		}
		if emb.Status != "NotSigned" && emb.IsSelfSigned {
			if err := stripEmbeddedSignature(filename); err != nil {
				return false, err
			}
			removed = true
		}
	}

	side, err := sidecarStatus(filename)
	if err != nil {
		return removed, err
	}
	if side.Status == "Sidecar" && side.IsSelfSigned {
		if err := os.Remove(filename + sidecarSuffix); err != nil {
			return removed, fmt.Errorf("failed to remove signature file: %w", err)
		}
		removed = true
	}

	return removed, nil
}

// stripEmbeddedSignature runs osslsigncode remove-signature and replaces the file.
func stripEmbeddedSignature(filename string) error {
	tmpOut := filepath.Join(filepath.Dir(filename), "."+filepath.Base(filename)+".stripping")
	out, err := runOsslsigncode("remove-signature", "-in", filename, "-out", tmpOut)
	if err != nil {
		os.Remove(tmpOut)
		return fmt.Errorf("osslsigncode remove-signature failed: %w: %s", err, strings.TrimSpace(out))
	}
	if err := os.Rename(tmpOut, filename); err != nil {
		os.Remove(tmpOut)
		return fmt.Errorf("failed to replace %s with unsigned copy: %w", filename, err)
	}
	return nil
}

// osslsigncodeTool locates the osslsigncode executable on PATH.
func osslsigncodeTool() (string, error) {
	path, err := exec.LookPath("osslsigncode")
	if err != nil {
		return "", fmt.Errorf("osslsigncode not found on PATH (install it for Authenticode signing, or use --sidecar-only): %w", err)
	}
	return path, nil
}

// osslsigncodeAvailable reports whether osslsigncode can be found.
func osslsigncodeAvailable() error {
	_, err := osslsigncodeTool()
	return err
}

// runOsslsigncode runs osslsigncode and returns its combined output.
func runOsslsigncode(args ...string) (string, error) {
	tool, err := osslsigncodeTool()
	if err != nil {
		return "", err
	}
	out, err := exec.Command(tool, args...).CombinedOutput()
	return string(out), err
}
