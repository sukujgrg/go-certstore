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
	winIdent, ok := ident.(*winIdentity)
	if !ok {
		t.Fatalf("unexpected identity type %T", ident)
	}

	ownedSigner, err := ident.Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseSigner(ownedSigner) })

	cachedSigner, err := winIdent.signer(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = CloseSigner(cachedSigner) })
	winSigner, ok := cachedSigner.(*winSigner)
	if !ok {
		t.Fatalf("unexpected signer type %T", cachedSigner)
	}
	if winSigner.callerFree {
		t.Fatal("cached private-key acquisition returned a caller-owned handle")
	}
	if winSigner.certCtx == nil {
		t.Fatal("cached private-key signer did not retain its certificate context")
	}

	// CRYPT_ACQUIRE_CACHE_FLAG makes the key handle certificate-context-owned.
	// The signer's duplicate context must keep that borrowed handle alive.
	ident.Close()
	digest := sha256.Sum256([]byte("go-certstore windows integration"))
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("unexpected public key type %T", cert.PublicKey)
	}
	for _, test := range []struct {
		name   string
		signer crypto.Signer
	}{
		{name: "normal", signer: ownedSigner},
		{name: "certificate-owned", signer: cachedSigner},
	} {
		sig, err := test.signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("%s signer after identity close: %v", test.name, err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("%s signature verification failed: %v", test.name, err)
		}
		if err := CloseSigner(test.signer); err != nil {
			t.Fatalf("close %s signer: %v", test.name, err)
		}
		if _, err := test.signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrClosed) {
			t.Fatalf("%s signer after close: got %v, want ErrClosed", test.name, err)
		}
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
