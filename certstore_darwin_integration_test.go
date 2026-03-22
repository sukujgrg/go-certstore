//go:build darwin && cgo

package certstore

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMacKeychainIntegration(t *testing.T) {
	if os.Getenv("CERTSTORE_RUN_NATIVE_TESTS") != "1" {
		t.Skip("native macOS integration test disabled; set CERTSTORE_RUN_NATIVE_TESTS=1 to enable")
	}
	if _, err := exec.LookPath("security"); err != nil {
		t.Skip("security tool not available")
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}

	workspace := t.TempDir()
	keychainPath := filepath.Join(workspace, "go-certstore-test.keychain-db")
	keychainPassword := "go-certstore-test"
	testCN := "go-certstore-mac-" + time.Now().Format("20060102150405.000000000")

	origList := strings.TrimSpace(runDarwinCommandOutput(t, "", "security", "list-keychains", "-d", "user"))
	if origList != "" {
		t.Cleanup(func() {
			args := []string{"list-keychains", "-d", "user", "-s"}
			args = append(args, parseSecurityKeychains(origList)...)
			runDarwinCommand(t, "", "security", args...)
		})
	}
	t.Cleanup(func() {
		_, _ = runDarwinCommandResult("", "security", "delete-keychain", keychainPath)
	})

	if out, err := runDarwinCommandResult("", "security", "create-keychain", "-p", keychainPassword, keychainPath); err != nil {
		t.Skipf("temporary keychain creation unavailable: %v\n%s", err, strings.TrimSpace(string(out)))
	}
	runDarwinCommand(t, "", "security", "unlock-keychain", "-p", keychainPassword, keychainPath)
	runDarwinCommand(t, "", "security", "set-keychain-settings", keychainPath)
	keychains := append([]string{"list-keychains", "-d", "user", "-s", keychainPath}, parseSecurityKeychains(origList)...)
	runDarwinCommand(t, "", "security", keychains...)

	key, certPEM, keyPEM := newNativeTestMaterial(t, testCN)
	keyPath := filepath.Join(workspace, "key.pem")
	certPath := filepath.Join(workspace, "cert.pem")
	p12Path := filepath.Join(workspace, "identity.p12")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	exportArgs := []string{
		"pkcs12", "-export",
		"-inkey", keyPath,
		"-in", certPath,
		"-out", p12Path,
		"-name", testCN,
		"-passout", "pass:" + keychainPassword,
	}
	if opensslSupportsLegacyPKCS12() {
		exportArgs = append([]string{"pkcs12", "-export", "-legacy"}, exportArgs[2:]...)
	}
	runDarwinCommand(t, "", "openssl", exportArgs...)
	runDarwinCommand(t, "", "security", "import", p12Path, "-k", keychainPath, "-P", keychainPassword, "-A")
	runDarwinCommand(t, "", "security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", keychainPassword, keychainPath)

	store, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ident, err := FindIdentity(store, FindIdentityOptions{
		Backend:   BackendDarwin,
		SubjectCN: testCN,
		ValidOnly: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer ident.Close()

	cert, err := ident.Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != testCN {
		t.Fatalf("unexpected certificate CN %q", cert.Subject.CommonName)
	}

	signer, err := ident.Signer()
	if err != nil {
		t.Skipf("temporary keychain identity not usable for signing in this environment: %v", err)
	}
	digest := sha256.Sum256([]byte("go-certstore darwin integration"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Skipf("temporary keychain signing unavailable in this environment: %v", err)
	}
	if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("signature verification failed: %v", err)
	}
	if err := CloseSigner(signer); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrClosed) {
		t.Fatalf("expected ErrClosed after signer close, got %v", err)
	}
}

func parseSecurityKeychains(output string) []string {
	lines := strings.Split(output, "\n")
	var out []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		line = strings.Trim(line, "\"")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func newNativeTestMaterial(t *testing.T, commonName string) (*rsa.PrivateKey, []byte, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return key, certPEM, keyPEM
}

func runDarwinCommandOutput(t *testing.T, dir, path string, args ...string) string {
	t.Helper()

	out, err := runDarwinCommandResult(dir, path, args...)
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, string(out))
	}
	return string(out)
}

func runDarwinCommand(t *testing.T, dir, path string, args ...string) {
	t.Helper()

	out, err := runDarwinCommandResult(dir, path, args...)
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, string(out))
	}
}

func runDarwinCommandResult(dir, path string, args ...string) ([]byte, error) {
	cmd := exec.Command(path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	return cmd.CombinedOutput()
}

func opensslSupportsLegacyPKCS12() bool {
	out, err := runDarwinCommandResult("", "openssl", "pkcs12", "-help")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "-legacy")
}
