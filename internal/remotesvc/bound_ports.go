package remotesvc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// BoundPort describes a TCP port currently listening on the remote host.
type BoundPort struct {
	Port    int    `json:"port"`
	Address string `json:"address"`
	Process string `json:"process,omitempty"`
}

const boundPortsScript = `
collect_ss() {
  if command -v ss >/dev/null 2>&1; then
    if [ "$(id -u)" = "0" ]; then
      ss -tlnpH 2>/dev/null && return 0
    fi
    if command -v sudo >/dev/null 2>&1; then
      sudo -n ss -tlnpH 2>/dev/null && return 0
    fi
    ss -tlnpH 2>/dev/null && return 0
    ss -tlnH 2>/dev/null && return 0
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -tlnp 2>/dev/null | tail -n +3 && return 0
    netstat -tln 2>/dev/null | tail -n +3 && return 0
  fi
  echo "ERROR=no ss or netstat" >&2
  return 1
}

collect_ss | awk '
{
  line=$0
  local=$4
  port=""
  addr=""
  if (substr(local, 1, 1) == "[") {
    addr=local
    sub(/^\[/, "", addr)
    sub(/\]:[^:]+$/, "", addr)
    port=local
    sub(/^[^\]]*\]:/, "", port)
  } else {
    n=split(local, parts, ":")
    port=parts[n]
    addr=local
    sub(/:[0-9]+$/, "", addr)
    sub(/%[^:]*$/, "", addr)
  }
  gsub(/[^0-9].*$/, "", port)
  if (port == "" || port+0 < 1 || port+0 > 65535) next
  if (addr == "") addr="*"

  proc=""
  if (match(line, /users:\(\(\"[^\"]+\"/)) {
    proc=substr(line, RSTART + 9, RLENGTH - 9)
    sub(/\".*/, "", proc)
  } else if (NF >= 7 && $NF ~ /\//) {
    proc=$NF
    sub(/^[0-9]+\//, "", proc)
    if (proc == "-") proc=""
  }

  printf "PORT=%s\nADDR=%s\nPROC=%s\n---\n", port, addr, proc
}'
`

func parseBoundPortsOutput(raw string) ([]BoundPort, error) {
	seen := make(map[int]BoundPort)
	var current map[string]string

	flush := func() {
		if current == nil {
			return
		}
		port, err := strconv.Atoi(strings.TrimSpace(current["PORT"]))
		if err != nil || port < 1 || port > 65535 {
			current = nil
			return
		}
		entry := BoundPort{
			Port:    port,
			Address: strings.TrimSpace(current["ADDR"]),
			Process: strings.TrimSpace(current["PROC"]),
		}
		if entry.Address == "" {
			entry.Address = "*"
		}
		if existing, ok := seen[port]; !ok || entry.Process != "" && existing.Process == "" {
			seen[port] = entry
		}
		current = nil
	}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "---" {
			flush()
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		if current == nil {
			current = map[string]string{}
		}
		current[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	flush()

	ports := make([]BoundPort, 0, len(seen))
	for _, entry := range seen {
		ports = append(ports, entry)
	}
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[j].Port < ports[i].Port {
				ports[i], ports[j] = ports[j], ports[i]
			}
		}
	}
	return ports, nil
}

// ProbeBoundPorts SSHes to the target and lists TCP ports in LISTEN state.
func ProbeBoundPorts(ctx context.Context, target SSHTarget) ([]BoundPort, error) {
	client, err := dialSSH(ctx, target)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	out, err := runRemoteScript(client, boundPortsScript)
	if err != nil {
		return nil, fmt.Errorf("probe bound ports: %w", err)
	}
	return parseBoundPortsOutput(string(out))
}

func BoundPortNumbers(ports []BoundPort) map[int]struct{} {
	set := make(map[int]struct{}, len(ports))
	for _, port := range ports {
		set[port.Port] = struct{}{}
	}
	return set
}
