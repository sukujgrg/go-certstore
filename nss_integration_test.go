//go:build cgo

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
	"runtime"
	"testing"
	"time"
)

func TestNSSIntegration(t *testing.T) {
	certutilPath, pk12utilPath, modulePath, opensslPath := findNSSTestTools()
	if certutilPath == "" || pk12utilPath == "" || modulePath == "" || opensslPath == "" {
		t.Skip("NSS tooling not available")
	}

	workspace := t.TempDir()
	profileDir := filepath.Join(workspace, "nssdb")
	if err := os.MkdirAll(profileDir, 0o755); err != nil {
		t.Fatal(err)
	}

	runNSSCommand(t, "", certutilPath, "-N", "-d", "sql:"+profileDir, "--empty-password")

	key, certPEM, keyPEM := newNSSTestMaterial(t)
	keyPath := filepath.Join(workspace, "key.pem")
	certPath := filepath.Join(workspace, "cert.pem")
	p12Path := filepath.Join(workspace, "identity.p12")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	runNSSCommand(t, "", opensslPath,
		"pkcs12", "-export",
		"-inkey", keyPath,
		"-in", certPath,
		"-out", p12Path,
		"-name", "nss-client",
		"-passout", "pass:",
	)
	runNSSCommand(t, "", pk12utilPath, "-i", p12Path, "-d", "sql:"+profileDir, "-W", "")

	store, err := Open(
		WithBackend(BackendNSS),
		WithNSSModule(modulePath),
		WithNSSProfileDir(profileDir),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		t.Fatal(err)
	}
	if len(idents) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(idents))
	}
	defer idents[0].Close()

	cert, err := idents[0].Certificate()
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "nss-client.example.com" {
		t.Fatalf("unexpected certificate CN %q", cert.Subject.CommonName)
	}
	chain, err := idents[0].CertificateChain()
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 1 {
		t.Fatalf("expected self-signed chain length 1, got %d", len(chain))
	}

	info, ok := idents[0].(NSSIdentityInfo)
	if !ok {
		t.Fatal("expected NSS identity to implement NSSIdentityInfo")
	}
	if info.ProfileDir() != profileDir {
		t.Fatalf("unexpected profile dir %q", info.ProfileDir())
	}
	if info.ModulePath() != modulePath {
		t.Fatalf("unexpected module path %q", info.ModulePath())
	}
	if info.Backend() != BackendNSS {
		t.Fatalf("unexpected backend %q", info.Backend())
	}

	signer, err := idents[0].Signer()
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("go-certstore nss integration"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
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

func newNSSTestMaterial(t *testing.T) (*rsa.PrivateKey, []byte, []byte) {
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
			CommonName: "nss-client.example.com",
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

func findNSSTestTools() (certutilPath, pk12utilPath, modulePath, opensslPath string) {
	if env := os.Getenv("NSS_CERTUTIL"); env != "" {
		certutilPath = env
	} else if path, err := exec.LookPath("certutil"); err == nil {
		certutilPath = path
	}
	if env := os.Getenv("NSS_PK12UTIL"); env != "" {
		pk12utilPath = env
	} else if path, err := exec.LookPath("pk12util"); err == nil {
		pk12utilPath = path
	}
	if env := os.Getenv("NSS_MODULE"); env != "" {
		modulePath = env
	}
	if path, err := exec.LookPath("openssl"); err == nil {
		opensslPath = path
	}

	candidates := nssToolCandidates()
	if certutilPath == "" {
		for _, candidate := range candidates.certutilPaths {
			if _, err := os.Stat(candidate); err == nil {
				certutilPath = candidate
				break
			}
		}
	}
	if pk12utilPath == "" {
		for _, candidate := range candidates.pk12utilPaths {
			if _, err := os.Stat(candidate); err == nil {
				pk12utilPath = candidate
				break
			}
		}
	}
	if modulePath == "" {
		for _, candidate := range candidates.modulePaths {
			if _, err := os.Stat(candidate); err == nil {
				modulePath = candidate
				break
			}
		}
	}
	return certutilPath, pk12utilPath, modulePath, opensslPath
}

type nssPathCandidates struct {
	certutilPaths []string
	pk12utilPaths []string
	modulePaths   []string
}

func nssToolCandidates() nssPathCandidates {
	switch runtime.GOOS {
	case "darwin":
		return nssPathCandidates{
			certutilPaths: []string{
				"/opt/homebrew/bin/certutil",
				"/usr/local/bin/certutil",
			},
			pk12utilPaths: []string{
				"/opt/homebrew/bin/pk12util",
				"/usr/local/bin/pk12util",
			},
			modulePaths: []string{
				"/opt/homebrew/lib/libsoftokn3.dylib",
				"/usr/local/lib/libsoftokn3.dylib",
			},
		}
	default:
		return nssPathCandidates{
			certutilPaths: []string{
				"/usr/bin/certutil",
				"/usr/local/bin/certutil",
			},
			pk12utilPaths: []string{
				"/usr/bin/pk12util",
				"/usr/local/bin/pk12util",
			},
			modulePaths: []string{
				"/usr/lib/x86_64-linux-gnu/nss/libsoftokn3.so",
				"/usr/lib64/libsoftokn3.so",
				"/usr/lib/libsoftokn3.so",
				"/usr/lib/nss/libsoftokn3.so",
				"/usr/local/lib/libsoftokn3.so",
			},
		}
	}
}

func runNSSCommand(t *testing.T, dir, path string, args ...string) {
	t.Helper()

	cmd := exec.Command(path, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", path, args, err, string(out))
	}
}
