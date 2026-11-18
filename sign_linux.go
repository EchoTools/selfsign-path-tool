//go:build linux

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func installCertificateToStorePlatform(certInterface interface{}) error {
	cert, ok := certInterface.(*x509.Certificate)
	if !ok {
		return fmt.Errorf("invalid certificate type")
	}

	// Try to install to system certificate store
	// Different distributions have different locations and tools
	return installCertificateLinuxSystem(cert)
}

// installCertificateLinuxSystem tries to install certificate to system store
func installCertificateLinuxSystem(cert *x509.Certificate) error {
	// Common certificate directories on Linux
	certDirs := []string{
		"/usr/local/share/ca-certificates",
		"/etc/ssl/certs",
		"/etc/pki/ca-trust/source/anchors",
	}

	certName := fmt.Sprintf("selfsign-path-%s.crt", cert.Subject.CommonName)
	
	// Try each directory
	for _, certDir := range certDirs {
		if _, err := os.Stat(certDir); err != nil {
			continue // Directory doesn't exist
		}
		
		certPath := filepath.Join(certDir, certName)
		
		// Try to write certificate
		if err := os.WriteFile(certPath, cert.Raw, 0644); err != nil {
			continue // Can't write to this directory
		}
		
		// Try to update certificate store
		updateCertStore(certDir)
		
		fmt.Printf("Certificate installed to: %s\n", certPath)
		return nil
	}
	
	// If system installation fails, install to user directory
	return installCertificateLinuxUser(cert)
}

// installCertificateLinuxUser installs certificate to user certificate store
func installCertificateLinuxUser(cert *x509.Certificate) error {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get user home directory: %w", err)
	}
	
	// Create user certificate directory
	certDir := filepath.Join(homeDir, ".local", "share", "ca-certificates")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create user certificate directory: %w", err)
	}
	
	certName := fmt.Sprintf("selfsign-path-%s.crt", cert.Subject.CommonName)
	certPath := filepath.Join(certDir, certName)
	
	if err := os.WriteFile(certPath, cert.Raw, 0644); err != nil {
		return fmt.Errorf("failed to write certificate to user directory: %w", err)
	}
	
	fmt.Printf("Certificate installed to user directory: %s\n", certPath)
	fmt.Printf("Note: Certificate may not be trusted system-wide without administrator privileges.\n")
	
	return nil
}

// updateCertStore runs commands to update the certificate store
func updateCertStore(certDir string) {
	// Try different update commands based on the certificate directory
	switch {
	case strings.Contains(certDir, "ca-certificates"):
		// Debian/Ubuntu
		exec.Command("update-ca-certificates").Run()
	case strings.Contains(certDir, "ca-trust"):
		// Red Hat/CentOS/Fedora
		exec.Command("update-ca-trust").Run()
	}
}