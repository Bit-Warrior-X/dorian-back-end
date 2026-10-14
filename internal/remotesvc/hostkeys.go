package remotesvc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

// KnownHostStore persists the SSH host key pinned for each host:port.
type KnownHostStore interface {
	// LookupHostKey returns the pinned key in authorized_keys format, or "" if none.
	LookupHostKey(ctx context.Context, hostPort string) (string, error)
	// RememberHostKey pins key unless one is already pinned, and returns the pinned key.
	RememberHostKey(ctx context.Context, hostPort, key, fingerprint string) (string, error)
}

var (
	knownHostsMu sync.RWMutex
	knownHosts   KnownHostStore
)

// SetKnownHostStore installs the store used to verify edge SSH host keys.
func SetKnownHostStore(store KnownHostStore) {
	knownHostsMu.Lock()
	knownHosts = store
	knownHostsMu.Unlock()
}

func currentKnownHostStore() KnownHostStore {
	knownHostsMu.RLock()
	defer knownHostsMu.RUnlock()
	return knownHosts
}

// ForgetHostKeys drops pins so the next connection trusts the key it sees.
func ForgetHostKeys(ctx context.Context, hostPorts ...string) error {
	forgetter, ok := currentKnownHostStore().(interface {
		ForgetHostKey(ctx context.Context, hostPorts ...string) error
	})
	if !ok {
		return errors.New("ssh host key store does not support reset")
	}
	return forgetter.ForgetHostKey(ctx, hostPorts...)
}

// HostKeyMismatchError means the edge presented a different key than the one
// pinned on first contact (reinstalled host, changed IP owner, or MITM).
type HostKeyMismatchError struct {
	HostPort string
	Expected string
	Got      string
}

func (e *HostKeyMismatchError) Error() string {
	return fmt.Sprintf(
		"SSH host key for %s changed (now %s). If the edge was reinstalled, reset its SSH host key in Edit Edge",
		e.HostPort, e.Got,
	)
}

func IsHostKeyMismatch(err error) bool {
	var target *HostKeyMismatchError
	return errors.As(err, &target)
}

// HostPort is the key used for pinning: host plus SSH port (default 22).
func HostPort(host, port string) string {
	return SSHTarget{Host: host, Port: port}.dialAddr()
}

func fingerprintOf(authorizedKey string) string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "unparseable key"
	}
	return ssh.FingerprintSHA256(pub)
}

// hostKeyAlgorithmsFor restricts negotiation to the pinned key's type so the
// server cannot switch to a different (unpinned) key type.
func hostKeyAlgorithmsFor(authorizedKey string) []string {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil
	}
	if pub.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	return []string{pub.Type()}
}

// hostKeyPolicy returns the callback and allowed algorithms for hostPort:
// verify against the pinned key, or pin the first key seen (trust on first use).
func hostKeyPolicy(ctx context.Context, hostPort string) (ssh.HostKeyCallback, []string, error) {
	store := currentKnownHostStore()
	if store == nil {
		return nil, nil, errors.New("ssh host key store is not configured")
	}
	pinned, err := store.LookupHostKey(ctx, hostPort)
	if err != nil {
		return nil, nil, fmt.Errorf("load trusted ssh host key: %w", err)
	}
	pinned = strings.TrimSpace(pinned)

	callback := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		presented := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		expected := pinned
		if expected == "" {
			stored, err := store.RememberHostKey(ctx, hostPort, presented, ssh.FingerprintSHA256(key))
			if err != nil {
				return fmt.Errorf("save trusted ssh host key: %w", err)
			}
			expected = strings.TrimSpace(stored)
		}
		if expected != presented {
			return &HostKeyMismatchError{
				HostPort: hostPort,
				Expected: fingerprintOf(expected),
				Got:      ssh.FingerprintSHA256(key),
			}
		}
		return nil
	}
	var algorithms []string
	if pinned != "" {
		algorithms = hostKeyAlgorithmsFor(pinned)
	}
	return callback, algorithms, nil
}
