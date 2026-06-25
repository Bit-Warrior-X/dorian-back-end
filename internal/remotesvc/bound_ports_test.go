package remotesvc

import "testing"

func TestParseBoundPortsOutput(t *testing.T) {
	raw := `PORT=80
ADDR=0.0.0.0
PROC=nginx
---
PORT=443
ADDR=0.0.0.0
PROC=nginx
---
PORT=5000
ADDR=127.0.0.1
PROC=python
---
PORT=53
ADDR=127.0.0.53
PROC=systemd-resolve
---
`
	got, err := parseBoundPortsOutput(raw)
	if err != nil {
		t.Fatalf("parseBoundPortsOutput: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 ports, got %d", len(got))
	}
	byPort := map[int]BoundPort{}
	for _, entry := range got {
		byPort[entry.Port] = entry
	}
	if entry := byPort[80]; entry.Process != "nginx" {
		t.Fatalf("unexpected port 80: %+v", entry)
	}
	if entry := byPort[53]; entry.Address != "127.0.0.53" || entry.Process != "systemd-resolve" {
		t.Fatalf("unexpected port 53: %+v", entry)
	}
}

func TestParseBoundPortsOutputPrefersNamedProcess(t *testing.T) {
	raw := `PORT=22
ADDR=0.0.0.0
PROC=
---
PORT=22
ADDR=0.0.0.0
PROC=sshd
---
`
	got, err := parseBoundPortsOutput(raw)
	if err != nil {
		t.Fatalf("parseBoundPortsOutput: %v", err)
	}
	if len(got) != 1 || got[0].Process != "sshd" {
		t.Fatalf("expected sshd process, got %+v", got)
	}
}
