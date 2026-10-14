package remotesvc

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// DialSSH opens an SSH connection to target with password auth and host-key
// pinning. Callers must Close the returned client.
func DialSSH(ctx context.Context, target SSHTarget) (*ssh.Client, error) {
	return dialSSH(ctx, target)
}

func dialSSH(ctx context.Context, target SSHTarget) (*ssh.Client, error) {
	user := strings.TrimSpace(target.User)
	if user == "" {
		return nil, fmt.Errorf("ssh user is required")
	}
	if strings.TrimSpace(target.Host) == "" {
		return nil, fmt.Errorf("ssh host is required")
	}

	auth, err := authMethods(target)
	if err != nil {
		return nil, err
	}
	addr := target.dialAddr()
	hostKeyCallback, hostKeyAlgorithms, err := hostKeyPolicy(ctx, addr)
	if err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:              user,
		Auth:              auth,
		HostKeyCallback:   hostKeyCallback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           defaultDialTimeout,
	}

	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}
	return ssh.NewClient(cc, chans, reqs), nil
}

// ParsePrivateKey validates an SSH private key, using passphrase when the key is encrypted.
func ParsePrivateKey(privateKey, passphrase string) (ssh.Signer, error) {
	raw := []byte(strings.TrimSpace(privateKey) + "\n")
	if passphrase != "" {
		signer, err := ssh.ParsePrivateKeyWithPassphrase(raw, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("ssh private key: %w", err)
		}
		return signer, nil
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, errors.New("ssh private key is passphrase-protected; enter its passphrase")
		}
		return nil, fmt.Errorf("ssh private key: %w", err)
	}
	return signer, nil
}

// UnencryptedPrivateKeyPEM returns the key in OpenSSH PEM form without a passphrase,
// for tools such as `ssh -i` that cannot be given the passphrase non-interactively.
func UnencryptedPrivateKeyPEM(privateKey, passphrase string) (string, error) {
	privateKey = strings.TrimSpace(privateKey)
	if privateKey == "" {
		return "", nil
	}
	if passphrase == "" {
		if _, err := ParsePrivateKey(privateKey, ""); err != nil {
			return "", err
		}
		return privateKey + "\n", nil
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase([]byte(privateKey+"\n"), []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("ssh private key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(raw, "")
	if err != nil {
		return "", fmt.Errorf("ssh private key: %w", err)
	}
	return string(pem.EncodeToMemory(block)), nil
}

func authMethods(target SSHTarget) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if strings.TrimSpace(target.PrivateKey) != "" {
		signer, err := ParsePrivateKey(target.PrivateKey, target.KeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if target.Password != "" {
		methods = append(methods, ssh.Password(target.Password))
	}
	if len(methods) == 0 {
		return nil, errors.New("ssh password or private key is required")
	}
	return methods, nil
}

func runRemoteScript(client *ssh.Client, script string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	_ = session.Setenv("LANG", "C")
	out, err := session.CombinedOutput(script)
	if err != nil {
		if len(out) > 0 {
			return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
		}
		return out, err
	}
	return out, nil
}
