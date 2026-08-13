package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	path = filepath.Clean(path)
	if raw, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, fmt.Errorf("acme account key %s is not PEM", path)
		}
		parsed, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			key, pkcs8Err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if pkcs8Err != nil {
				return nil, fmt.Errorf("parse acme account key: %w", err)
			}
			ecKey, ok := key.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("acme account key must be ECDSA")
			}
			return ecKey, nil
		}
		return parsed, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func encodePrivateKey(key crypto.Signer) ([]byte, error) {
	switch typed := key.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(typed)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
	default:
		der, err := x509.MarshalPKCS8PrivateKey(typed)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
}

func encodeCertificates(ders [][]byte) []byte {
	var out []byte
	for _, der := range ders {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return out
}
