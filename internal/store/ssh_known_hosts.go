package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// SSHKnownHostStore pins the SSH host key of each edge (host:port) on first contact.
type SSHKnownHostStore interface {
	LookupHostKey(ctx context.Context, hostPort string) (string, error)
	RememberHostKey(ctx context.Context, hostPort, key, fingerprint string) (string, error)
	ForgetHostKey(ctx context.Context, hostPorts ...string) error
}

type sshKnownHostStore struct {
	db *sql.DB
}

func NewSSHKnownHostStore(db *sql.DB) SSHKnownHostStore {
	return &sshKnownHostStore{db: db}
}

func (s *sshKnownHostStore) LookupHostKey(ctx context.Context, hostPort string) (string, error) {
	var key string
	err := s.db.QueryRowContext(ctx,
		`SELECT public_key FROM ssh_known_hosts WHERE host_port = ?`,
		strings.TrimSpace(hostPort),
	).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return key, err
}

// RememberHostKey keeps an existing pin (first writer wins) and returns the pinned key.
func (s *sshKnownHostStore) RememberHostKey(ctx context.Context, hostPort, key, fingerprint string) (string, error) {
	hostPort = strings.TrimSpace(hostPort)
	if _, err := s.db.ExecContext(ctx,
		`INSERT IGNORE INTO ssh_known_hosts (host_port, public_key, fingerprint) VALUES (?, ?, ?)`,
		hostPort, strings.TrimSpace(key), strings.TrimSpace(fingerprint),
	); err != nil {
		return "", err
	}
	return s.LookupHostKey(ctx, hostPort)
}

func (s *sshKnownHostStore) ForgetHostKey(ctx context.Context, hostPorts ...string) error {
	for _, hostPort := range hostPorts {
		hostPort = strings.TrimSpace(hostPort)
		if hostPort == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM ssh_known_hosts WHERE host_port = ?`, hostPort); err != nil {
			return err
		}
	}
	return nil
}
