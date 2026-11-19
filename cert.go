package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Certificate represents a signing certificate
type Certificate struct {
	Subject    string
	Cert       *x509.Certificate
	PrivateKey *rsa.PrivateKey
}

// getCertificate obtains a certificate for signing - either from files or by creating one
func getCertificate() (*Certificate, error) {
	if *flagCertFile != "" && *flagKeyFile != "" {
		return loadCertificateFromFile(*flagCertFile, *flagKeyFile)
	}
	// No certificate or key is reused between runs. Each run gets a one-time key, which is
	// erased after signing and never written to the certificate directory.
	return createSelfSignedCertificate(*flagName)
}

// loadCertificateFromFile loads a certificate and private key from files
func loadCertificateFromFile(certFile, keyFile string) (*Certificate, error) {
	// Load certificate file
	certData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file %s: %w", certFile, err)
	}

	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate from %s", certFile)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate from %s: %w", certFile, err)
	}

	// Load private key file
	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", keyFile, err)
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM private key from %s", keyFile)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key from %s: %w", keyFile, err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key from %s is not an RSA key", keyFile)
		}
	}

	return &Certificate{
		Subject:    cert.Subject.CommonName,
		Cert:       cert,
		PrivateKey: privateKey,
	}, nil
}

// createSelfSignedCertificate creates a new self-signed certificate
func createSelfSignedCertificate(subjectName string) (*Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: subjectName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	// The private key is deliberately not written to disk. The only on-disk copy is the
	// temporary file that signing needs, which is erased once each file is signed.

	// Try to install certificate to system store (platform-specific)
	if err := installCertificateToStore(cert); err != nil {
		fmt.Printf("Warning: Failed to install certificate to system store: %v\n", err)
		fmt.Printf("Certificate created but not installed to system trust store.\n")
	} else {
		fmt.Printf("Certificate installed to system trust store.\n")
	}

	return &Certificate{
		Subject:    subjectName,
		Cert:       cert,
		PrivateKey: privateKey,
	}, nil
}

// getCertificateDirectory returns the directory where certificates are stored
func getCertificateDirectory() string {
	var certDir string
	
	if runtime.GOOS == "windows" {
		// Use AppData on Windows
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
		certDir = filepath.Join(appData, "selfsign-path-tool", "certificates")
	} else {
		// Use ~/.local/share on Unix-like systems
		homeDir, err := os.UserHomeDir()
		if err != nil {
			// Fallback to /tmp
			certDir = "/tmp/selfsign-path-tool-certificates"
		} else {
			certDir = filepath.Join(homeDir, ".local", "share", "selfsign-path-tool", "certificates")
		}
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(certDir, 0700); err != nil {
		fmt.Printf("Warning: Failed to create certificate directory %s: %v\n", certDir, err)
	}

	return certDir
}
