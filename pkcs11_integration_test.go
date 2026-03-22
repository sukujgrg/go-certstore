//go:build cgo

package certstore

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/pkcs11"
)

func TestPKCS11SoftHSMIntegration(t *testing.T) {
	utilPath, modulePath := findSoftHSMPaths()
	if utilPath == "" || modulePath == "" {
		t.Skip("SoftHSM tooling not available")
	}

	workspace := t.TempDir()
	tokenDir := filepath.Join(workspace, "tokens")
	if err := os.MkdirAll(tokenDir, 0o755); err != nil {
		t.Fatal(err)
	}

	confPath := filepath.Join(workspace, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n"
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	tokenLabel := "go-certstore-test"
	userPIN := "123456"
	soPIN := "654321"
	keyLabel := "integration-key"
	keyID := "01"
	caLabel := "integration-ca"
	caID := "ca"

	runSoftHSM(t, utilPath, modulePath, confPath,
		"--init-token", "--free",
		"--label", tokenLabel,
		"--so-pin", soPIN,
		"--pin", userPIN,
	)

	key, leafCertPEM, caCertPEM, keyPEM := newSoftHSMTestMaterial(t)
	keyPath := filepath.Join(workspace, "key.pem")
	leafCertPath := filepath.Join(workspace, "leaf-cert.pem")
	caCertPath := filepath.Join(workspace, "ca-cert.pem")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leafCertPath, leafCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caCertPath, caCertPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	runSoftHSM(t, utilPath, modulePath, confPath,
		"--import", keyPath,
		"--import-type", "keypair",
		"--token", tokenLabel,
		"--label", keyLabel,
		"--id", keyID,
		"--pin", userPIN,
	)
	actualKeyID, actualKeyLabel := discoverSoftHSMPrivateKey(t, modulePath, tokenLabel, userPIN)
	if len(actualKeyID) == 0 {
		t.Skip("SoftHSM import did not expose a private key object in this environment")
	}
	if len(actualKeyID) != 0 {
		keyID = hex.EncodeToString(actualKeyID)
	}
	if actualKeyLabel != "" {
		keyLabel = actualKeyLabel
	}
	runSoftHSM(t, utilPath, modulePath, confPath,
		"--import", leafCertPath,
		"--import-type", "cert",
		"--token", tokenLabel,
		"--label", keyLabel,
		"--id", keyID,
		"--pin", userPIN,
	)
	runSoftHSM(t, utilPath, modulePath, confPath,
		"--import", caCertPath,
		"--import-type", "cert",
		"--token", tokenLabel,
		"--label", caLabel,
		"--id", caID,
		"--pin", userPIN,
	)

	store, err := Open(context.Background(),
		WithBackend(BackendPKCS11),
		WithPKCS11Module(modulePath),
		WithPKCS11TokenLabel(tokenLabel),
		WithCredentialPrompt(func(PromptInfo) (string, error) {
			return userPIN, nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	idents, err := store.Identities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(idents) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(idents))
	}
	defer idents[0].Close()

	cert, err := idents[0].Certificate(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "pkcs11-client.example.com" {
		t.Fatalf("unexpected certificate CN %q", cert.Subject.CommonName)
	}
	chain, err := idents[0].CertificateChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) != 2 {
		t.Fatalf("expected leaf+CA chain, got %d certs", len(chain))
	}
	if chain[1].Subject.CommonName != "pkcs11-test-ca" {
		t.Fatalf("unexpected issuer certificate %q", chain[1].Subject.CommonName)
	}

	info, ok := idents[0].(IdentityInfo)
	if !ok {
		t.Fatal("expected pkcs11 identity to implement IdentityInfo")
	}
	if info.Backend() != BackendPKCS11 {
		t.Fatalf("unexpected backend %q", info.Backend())
	}
	if !strings.Contains(info.URI(), "pkcs11:") {
		t.Fatalf("unexpected identity URI %q", info.URI())
	}
	p11Info, ok := idents[0].(PKCS11IdentityInfo)
	if !ok {
		t.Fatal("expected pkcs11 identity to implement PKCS11IdentityInfo")
	}
	if p11Info.TokenLabel() != tokenLabel {
		t.Fatalf("unexpected token label %q", p11Info.TokenLabel())
	}
	if p11Info.ModulePath() != modulePath {
		t.Fatalf("unexpected module path %q", p11Info.ModulePath())
	}

	signer, err := idents[0].Signer(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte("go-certstore pkcs11 integration"))
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

func discoverSoftHSMPrivateKey(t *testing.T, modulePath, tokenLabel, userPIN string) ([]byte, string) {
	t.Helper()

	ctx := pkcs11.New(modulePath)
	if ctx == nil {
		t.Fatal("pkcs11.New returned nil")
	}
	defer ctx.Destroy()
	if err := ctx.Initialize(); err != nil {
		t.Fatalf("initialize pkcs11 module: %v", err)
	}
	defer func() {
		_ = ctx.Finalize()
	}()

	slotID, _, _, err := selectPKCS11Slot(ctx, nil, tokenLabel)
	if err != nil {
		t.Fatalf("select pkcs11 slot: %v", err)
	}

	session, err := ctx.OpenSession(slotID, pkcs11.CKF_SERIAL_SESSION)
	if err != nil {
		t.Fatalf("open pkcs11 session: %v", err)
	}
	defer func() {
		_ = ctx.CloseSession(session)
	}()

	if err := ctx.Login(session, pkcs11.CKU_USER, userPIN); err != nil && !isPKCS11Error(err, pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
		t.Fatalf("login to pkcs11 session: %v", err)
	}
	defer func() {
		_ = ctx.Logout(session)
	}()

	objects, err := findPKCS11Objects(ctx, session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	})
	if err != nil {
		t.Fatalf("find private key objects: %v", err)
	}
	if len(objects) != 1 {
		t.Logf("expected 1 private key object after import, got %d", len(objects))
		return nil, ""
	}

	attrs, err := ctx.GetAttributeValue(session, objects[0], []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, nil),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, nil),
	})
	if err != nil {
		t.Fatalf("read private key attributes: %v", err)
	}
	return cloneBytes(attrs[0].Value), strings.TrimSpace(string(attrs[1].Value))
}

func newSoftHSMTestMaterial(t *testing.T) (*rsa.PrivateKey, []byte, []byte, []byte) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: "pkcs11-test-ca",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          []byte{0xCA, 0x01},
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

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
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject: pkix.Name{
			CommonName: "pkcs11-client.example.com",
		},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		AuthorityKeyId: caCert.SubjectKeyId,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return key, leafCertPEM, caCertPEM, keyPEM
}

func runSoftHSM(t *testing.T, utilPath, modulePath, confPath string, args ...string) {
	t.Helper()

	cmdArgs := append([]string{"--module", modulePath}, args...)
	cmd := exec.Command(utilPath, cmdArgs...)
	cmd.Env = append(os.Environ(), "SOFTHSM2_CONF="+confPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("softhsm2-util %v failed: %v\n%s", args, err, string(out))
	}
}

func findSoftHSMPaths() (utilPath, modulePath string) {
	if env := os.Getenv("SOFTHSM2_UTIL"); env != "" {
		utilPath = env
	} else if path, err := exec.LookPath("softhsm2-util"); err == nil {
		utilPath = path
	}
	if env := os.Getenv("SOFTHSM2_MODULE"); env != "" {
		modulePath = env
	}

	candidates := softHSMCandidates()
	if utilPath == "" {
		for _, candidate := range candidates.utilPaths {
			if _, err := os.Stat(candidate); err == nil {
				utilPath = candidate
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
	return utilPath, modulePath
}

type softHSMPathCandidates struct {
	utilPaths   []string
	modulePaths []string
}

func softHSMCandidates() softHSMPathCandidates {
	switch runtime.GOOS {
	case "darwin":
		return softHSMPathCandidates{
			utilPaths: []string{
				"/opt/homebrew/bin/softhsm2-util",
				"/opt/homebrew/Cellar/softhsm/2.7.0/bin/softhsm2-util",
				"/usr/local/bin/softhsm2-util",
			},
			modulePaths: []string{
				"/opt/homebrew/lib/softhsm/libsofthsm2.so",
				"/opt/homebrew/Cellar/softhsm/2.7.0/lib/softhsm/libsofthsm2.so",
				"/usr/local/lib/softhsm/libsofthsm2.so",
			},
		}
	default:
		return softHSMPathCandidates{
			utilPaths: []string{
				"/usr/bin/softhsm2-util",
				"/usr/local/bin/softhsm2-util",
			},
			modulePaths: []string{
				"/usr/lib/softhsm/libsofthsm2.so",
				"/usr/lib64/softhsm/libsofthsm2.so",
				"/usr/local/lib/softhsm/libsofthsm2.so",
			},
		}
	}
}
