package remotesvc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

type memoryKnownHosts struct {
	mu   sync.Mutex
	keys map[string]string
}

func (m *memoryKnownHosts) LookupHostKey(_ context.Context, hostPort string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[hostPort], nil
}

func (m *memoryKnownHosts) RememberHostKey(_ context.Context, hostPort, key, _ string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[hostPort]; !ok {
		m.keys[hostPort] = key
	}
	return m.keys[hostPort], nil
}

func (m *memoryKnownHosts) ForgetHostKey(_ context.Context, hostPorts ...string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, hp := range hostPorts {
		delete(m.keys, hp)
	}
	return nil
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// startTestSSHServer accepts password "pw" and completes handshakes until the test ends.
func startTestSSHServer(t *testing.T, hostKey ssh.Signer) (host, port string) {
	t.Helper()
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if string(pass) == "pw" {
				return nil, nil
			}
			return nil, ssh.ErrNoAuth
		},
	}
	cfg.AddHostKey(hostKey)
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

func TestDialSSHPinsAndVerifiesHostKey(t *testing.T) {
	store := &memoryKnownHosts{keys: map[string]string{}}
	SetKnownHostStore(store)
	t.Cleanup(func() { SetKnownHostStore(nil) })

	serverKey := newSigner(t)
	host, port := startTestSSHServer(t, serverKey)
	target := SSHTarget{Host: host, User: "root", Password: "pw", Port: port}
	hostPort := HostPort(host, port)
	ctx := context.Background()

	client, err := DialSSH(ctx, target)
	if err != nil {
		t.Fatalf("first dial (trust on first use): %v", err)
	}
	_ = client.Close()
	want := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(serverKey.PublicKey())))
	if got, _ := store.LookupHostKey(ctx, hostPort); got != want {
		t.Fatalf("pinned key = %q, want %q", got, want)
	}

	client, err = DialSSH(ctx, target)
	if err != nil {
		t.Fatalf("second dial with same key: %v", err)
	}
	_ = client.Close()

	impostor := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSigner(t).PublicKey())))
	store.keys[hostPort] = impostor
	if _, err := DialSSH(ctx, target); !IsHostKeyMismatch(err) {
		t.Fatalf("expected host key mismatch, got %v", err)
	}

	if err := ForgetHostKeys(ctx, hostPort); err != nil {
		t.Fatal(err)
	}
	client, err = DialSSH(ctx, target)
	if err != nil {
		t.Fatalf("dial after reset: %v", err)
	}
	_ = client.Close()
	if got, _ := store.LookupHostKey(ctx, hostPort); got != want {
		t.Fatalf("re-pinned key = %q, want %q", got, want)
	}
}

func TestDialSSHRequiresKnownHostStore(t *testing.T) {
	SetKnownHostStore(nil)
	if _, err := DialSSH(context.Background(), SSHTarget{Host: "127.0.0.1", User: "root", Port: "1"}); err == nil {
		t.Fatal("expected error without a known host store")
	}
}

func TestHostPortDefaultsTo22(t *testing.T) {
	if got := HostPort(" 10.0.0.1 ", ""); got != "10.0.0.1:22" {
		t.Fatalf("HostPort = %q", got)
	}
}
