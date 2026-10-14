package remotesvc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// startKeyOnlySSHServer accepts only the given client public key (no passwords).
func startKeyOnlySSHServer(t *testing.T, clientKey ssh.PublicKey) (host, port string) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientKey.Marshal()) {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(newSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					_ = conn.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "test server")
				}
				_ = sc.Close()
			}()
		}
	}()
	host, port, _ = net.SplitHostPort(ln.Addr().String())
	return host, port
}

func clientKeyPEM(t *testing.T, passphrase string) (string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var block *pem.Block
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(block)), sshPub
}

func TestDialSSHWithPrivateKey(t *testing.T) {
	SetKnownHostStore(&memoryKnownHosts{keys: map[string]string{}})
	t.Cleanup(func() { SetKnownHostStore(nil) })
	ctx := context.Background()

	for _, passphrase := range []string{"", "s3cret"} {
		keyPEM, pub := clientKeyPEM(t, passphrase)
		host, port := startKeyOnlySSHServer(t, pub)
		target := SSHTarget{Host: host, Port: port, User: "root", PrivateKey: keyPEM, KeyPassphrase: passphrase}

		client, err := DialSSH(ctx, target)
		if err != nil {
			t.Fatalf("passphrase=%q: key auth failed: %v", passphrase, err)
		}
		_ = client.Close()

		target.Password = "ignored-when-key-works"
		client, err = DialSSH(ctx, target)
		if err != nil {
			t.Fatalf("passphrase=%q: key+password failed: %v", passphrase, err)
		}
		_ = client.Close()
	}
}

func TestParsePrivateKeyErrors(t *testing.T) {
	encrypted, _ := clientKeyPEM(t, "pw")
	if _, err := ParsePrivateKey(encrypted, ""); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("missing passphrase: got %v", err)
	}
	if _, err := ParsePrivateKey(encrypted, "wrong"); err == nil {
		t.Fatal("wrong passphrase should fail")
	}
	if _, err := ParsePrivateKey("not a key", ""); err == nil {
		t.Fatal("garbage key should fail")
	}
	if _, err := DialSSH(context.Background(), SSHTarget{Host: "127.0.0.1", User: "root"}); err == nil {
		t.Fatal("no password and no key should fail")
	}
}
