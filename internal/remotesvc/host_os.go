package remotesvc

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

const hostOsDetectScript = `
if [ -r /etc/os-release ]; then
  . /etc/os-release
  printf '%s-%s' "${ID}" "${VERSION_ID}"
else
  exit 1
fi
`

// NormalizeHostOS lowercases and trims an OS slug (e.g. ubuntu-22.04).
func NormalizeHostOS(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// DetectHostOS SSHes to the target and reads /etc/os-release to produce a slug
// such as ubuntu-22.04, matching the versions.os column in deploy_license.
func DetectHostOS(ctx context.Context, target SSHTarget) (string, error) {
	user := strings.TrimSpace(target.User)
	if user == "" {
		return "", fmt.Errorf("ssh user is required")
	}
	if strings.TrimSpace(target.Host) == "" {
		return "", fmt.Errorf("ssh host is required")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(target.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultDialTimeout,
	}

	dialer := &net.Dialer{Timeout: defaultDialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target.dialAddr())
	if err != nil {
		return "", fmt.Errorf("ssh dial %s: %w", target.dialAddr(), err)
	}
	defer conn.Close()

	cc, chans, reqs, err := ssh.NewClientConn(conn, target.dialAddr(), config)
	if err != nil {
		return "", fmt.Errorf("ssh handshake %s: %w", target.dialAddr(), err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh session: %w", err)
	}
	defer session.Close()

	_ = session.Setenv("LANG", "C")
	out, err := session.CombinedOutput(hostOsDetectScript)
	if err != nil {
		return "", fmt.Errorf("detect host os: %w", err)
	}

	osSlug := NormalizeHostOS(string(out))
	if osSlug == "" || !strings.Contains(osSlug, "-") {
		return "", fmt.Errorf("detect host os: unexpected output %q", strings.TrimSpace(string(out)))
	}
	return osSlug, nil
}
