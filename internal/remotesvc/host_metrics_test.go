package remotesvc

import "testing"

func TestParseHostMetricsOutput(t *testing.T) {
	raw := `CPU=42.5
MEM_USED=4194304
MEM_TOTAL=8388608
DISK_USED=107374182400
DISK_TOTAL=536870912000
SWAP_USED=262144
SWAP_TOTAL=8388608
LOAD1=0.84
LOAD5=0.62
LOAD15=0.41
UPTIME=1234567
CORES=8
HOSTNAME=edge-01
KERNEL=6.8.0-45-generic
NET_IFACE=eth0
NET_RX_BPS=15728640
NET_TX_BPS=2097152
NET_LINK_MBPS=10000
TEMP_MC=46500
TEMP_LABEL=Package id 0
`
	got, err := parseHostMetricsOutput(raw)
	if err != nil {
		t.Fatalf("parseHostMetricsOutput: %v", err)
	}
	if got.CPUPercent != 42.5 {
		t.Fatalf("cpu = %v, want 42.5", got.CPUPercent)
	}
	if got.MemoryUsedBytes != 4194304*1024 {
		t.Fatalf("mem used = %d", got.MemoryUsedBytes)
	}
	if got.MemoryTotalBytes != 8388608*1024 {
		t.Fatalf("mem total = %d", got.MemoryTotalBytes)
	}
	if got.DiskUsedBytes != 107374182400 {
		t.Fatalf("disk used = %d", got.DiskUsedBytes)
	}
	if got.DiskTotalBytes != 536870912000 {
		t.Fatalf("disk total = %d", got.DiskTotalBytes)
	}
	if got.SwapUsedBytes != 262144*1024 || got.SwapTotalBytes != 8388608*1024 {
		t.Fatalf("swap = %d / %d", got.SwapUsedBytes, got.SwapTotalBytes)
	}
	if got.Load1 != 0.84 || got.Load5 != 0.62 || got.Load15 != 0.41 {
		t.Fatalf("load = %v %v %v", got.Load1, got.Load5, got.Load15)
	}
	if got.UptimeSeconds != 1234567 {
		t.Fatalf("uptime = %d", got.UptimeSeconds)
	}
	if got.CPUCores != 8 {
		t.Fatalf("cores = %d", got.CPUCores)
	}
	if got.TemperatureC == nil || *got.TemperatureC != 46.5 {
		t.Fatalf("temp = %v", got.TemperatureC)
	}
	if got.TemperatureLabel != "Package id 0" {
		t.Fatalf("temp label = %q", got.TemperatureLabel)
	}
	if got.NetRxBytesPerSec != 15728640 || got.NetTxBytesPerSec != 2097152 {
		t.Fatalf("net = %d / %d", got.NetRxBytesPerSec, got.NetTxBytesPerSec)
	}
	if got.NetLinkMbps == nil || *got.NetLinkMbps != 10000 {
		t.Fatalf("link = %v", got.NetLinkMbps)
	}
	if got.NetInterface != "eth0" || got.Hostname != "edge-01" || got.Kernel != "6.8.0-45-generic" {
		t.Fatalf("identity = %+v", got)
	}
}

func TestParseHostMetricsOutputOptionalSensors(t *testing.T) {
	raw := `CPU=1.0
MEM_USED=1024
MEM_TOTAL=2048
DISK_USED=10
DISK_TOTAL=20
NET_LINK_MBPS=-1
TEMP_MC=
`
	got, err := parseHostMetricsOutput(raw)
	if err != nil {
		t.Fatalf("parseHostMetricsOutput: %v", err)
	}
	if got.TemperatureC != nil {
		t.Fatalf("temp = %v, want nil", *got.TemperatureC)
	}
	if got.NetLinkMbps != nil {
		t.Fatalf("link = %v, want nil", *got.NetLinkMbps)
	}
	if got.NetRxBytesPerSec != 0 || got.SwapTotalBytes != 0 || got.CPUCores != 0 {
		t.Fatalf("defaults = %+v", got)
	}
}
