package remotesvc

import (
	"context"
	"fmt"
	"strings"
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
	client, err := dialSSH(ctx, target)
	if err != nil {
		return "", err
	}
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
