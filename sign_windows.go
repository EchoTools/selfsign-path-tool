//go:build windows

package main

import (
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// Windows API constants
const (
	CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x20000
	CERT_SYSTEM_STORE_CURRENT_USER  = 0x10000
	CERT_STORE_ADD_REPLACE_EXISTING = 3
)

// Windows DLL and function declarations
var (
	crypt32                = syscall.NewLazyDLL("crypt32.dll")
	procCertOpenSystemStore = crypt32.NewProc("CertOpenSystemStoreW")
	procCertAddCertificateContextToStore = crypt32.NewProc("CertAddCertificateContextToStore")
	procCertCreateCertificateContext = crypt32.NewProc("CertCreateCertificateContext")
	procCertCloseStore = crypt32.NewProc("CertCloseStore")
	procCertFreeCertificateContext = crypt32.NewProc("CertFreeCertificateContext")
)

// installCertificateToStorePlatform installs certificate to Windows certificate store
func installCertificateToStorePlatform(certInterface interface{}) error {
	cert, ok := certInterface.(*x509.Certificate)
	if !ok {
		return fmt.Errorf("invalid certificate type")
	}

	// Try to use PowerShell to install the certificate (fallback approach)
	return installCertificateWithPowerShell(cert)
}

// installCertificateWithPowerShell uses PowerShell to install the certificate
func installCertificateWithPowerShell(cert *x509.Certificate) error {
	// Create temporary certificate file
	tempDir := os.TempDir()
	certFile := filepath.Join(tempDir, "temp_cert.crt")
	
	// Write certificate to temporary file
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to create temporary certificate file: %w", err)
	}
	defer os.Remove(certFile)
	defer certOut.Close()
	
	if _, err := certOut.Write(cert.Raw); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}
	certOut.Close()
	
	// Use PowerShell to import the certificate
	cmd := exec.Command("powershell", "-Command", 
		fmt.Sprintf(`
		try {
			$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('%s')
			$store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
			$store.Add($cert)
			$store.Close()
			Write-Host 'Certificate installed successfully'
		} catch {
			Write-Error $_.Exception.Message
			exit 1
		}`, certFile))
	
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to install certificate via PowerShell: %w, output: %s", err, string(output))
	}
	
	return nil
}

// isRunningAsAdmin checks if the current process is running as administrator
func isRunningAsAdmin() bool {
	// Use Windows API IsUserAnAdmin from shell32.dll
	ret, _, _ := procIsUserAnAdmin.Call()
	return ret != 0
}