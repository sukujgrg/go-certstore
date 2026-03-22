//go:build windows && cgo

package certstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

var windowsThumbprintPattern = regexp.MustCompile(`^[A-Fa-f0-9]{40}$`)

func TestWindowsCertStoreIntegration(t *testing.T) {
	if os.Getenv("CERTSTORE_RUN_NATIVE_TESTS") != "1" {
		t.Skip("native Windows integration test disabled; set CERTSTORE_RUN_NATIVE_TESTS=1 to enable")
	}
	powershell := findWindowsPowerShell()
	if powershell == "" {
		t.Skip("powershell not available")
	}

	testCN := "go-certstore-win-" + strings.ReplaceAll(time.Now().Format("20060102150405.000000000"), ".", "")
	thumbprint, err := createWindowsTestCertificate(t, powershell, testCN)
	if err != nil {
		t.Skipf("temporary certificate creation unavailable in this environment: %v", err)
	}
	if windowsThumbprintPattern.MatchString(thumbprint) {
		t.Cleanup(func() {
			_, _ = runWindowsCommandResult("", powershell,
				"-NoProfile", "-NonInteractive", "-Command",
				fmt.Sprintf(`$ErrorActionPreference = 'Stop'
	Import-Module PKI -ErrorAction Stop
if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
	New-PSDrive -Name Cert -PSProvider Certificate -Root '\' | Out-Null
}
Remove-Item -Path 'Cert:\CurrentUser\My\%s' -ErrorAction SilentlyContinue`, thumbprint),
			)
		})
	}

	store, err := Open(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ident, err := FindIdentity(context.Background(), store, FindIdentityOptions{
		Backend:   BackendWindows,
		SubjectCN: testCN,
		ValidOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ident.Close()

	cert, err := ident.Certificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != testCN {
		t.Fatalf("unexpected certificate CN %q", cert.Subject.CommonName)
	}

	signer, err := ident.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("go-certstore windows integration"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", cert.PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	if err := CloseSigner(signer); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed after signer close, got %v", err)
	}
}

func findWindowsPowerShell() string {
	for _, candidate := range []string{"powershell.exe", "pwsh.exe", "powershell", "pwsh"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

func runCommand(t *testing.T, dir, path string, args ...string) {
	t.Helper()

	out, err := runWindowsCommandResult(dir, path, args...)
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, string(out))
	}
}

func runCommandOutput(t *testing.T, dir, path string, args ...string) string {
	t.Helper()

	out, err := runWindowsCommandResult(dir, path, args...)
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, string(out))
	}
	return string(out)
}

func runWindowsCommandResult(dir, path string, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

func createWindowsTestCertificate(t *testing.T, powershell, commonName string) (string, error) {
	t.Helper()

	script := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
Import-Module PKI -ErrorAction Stop
if (-not (Get-PSDrive -Name Cert -ErrorAction SilentlyContinue)) {
	New-PSDrive -Name Cert -PSProvider Certificate -Root '\' | Out-Null
}
$cert = New-SelfSignedCertificate -Subject 'CN=%s' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable -KeyAlgorithm RSA -KeyLength 2048 -KeySpec Signature -NotAfter (Get-Date).AddDays(2) -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2') -ErrorAction Stop
Write-Output $cert.Thumbprint`, commonName)

	out, err := runWindowsCommandResult("", powershell, "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	thumbprint := strings.TrimSpace(string(out))
	if thumbprint == "" {
		return "", errors.New("empty thumbprint from certificate creation")
	}
	if !windowsThumbprintPattern.MatchString(thumbprint) {
		return "", fmt.Errorf("unexpected thumbprint output %q", thumbprint)
	}
	return thumbprint, nil
}
