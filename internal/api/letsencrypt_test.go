package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"vue-project-backend/internal/store"
)

func testCertPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "a.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

func TestResolveCustomCertificate(t *testing.T) {
	cert, key := testCertPair(t)
	otherCert, otherKey := testCertPair(t)
	existing := &store.Site{SslType: "custom", SslCert: cert, SslCertKey: key}

	blankKey := store.SiteInput{SslType: "custom", SslCert: cert}
	if err := resolveCustomCertificate(existing, &blankKey); err != nil || blankKey.SslCertKey != key {
		t.Fatalf("blank key should reuse stored key: err=%v", err)
	}

	newPair := store.SiteInput{SslType: "custom", SslCert: otherCert, SslCertKey: otherKey}
	if err := resolveCustomCertificate(existing, &newPair); err != nil {
		t.Fatalf("matching new pair rejected: %v", err)
	}

	newCertOldKey := store.SiteInput{SslType: "custom", SslCert: otherCert}
	if err := resolveCustomCertificate(existing, &newCertOldKey); err == nil {
		t.Fatal("new certificate with the old stored key must be rejected")
	}

	mismatched := store.SiteInput{SslType: "custom", SslCert: cert, SslCertKey: otherKey}
	if err := resolveCustomCertificate(nil, &mismatched); err == nil {
		t.Fatal("mismatched pair must be rejected on create")
	}

	missing := store.SiteInput{SslType: "custom", SslCert: cert}
	if err := resolveCustomCertificate(nil, &missing); err == nil {
		t.Fatal("custom SSL without a key must be rejected on create")
	}

	managed := store.SiteInput{SslType: "letsencrypt"}
	if err := resolveCustomCertificate(nil, &managed); err != nil {
		t.Fatalf("non-custom SSL should be ignored: %v", err)
	}
}
