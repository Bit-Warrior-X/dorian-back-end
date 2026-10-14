package remotesvc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// HostMetrics holds normalized resource usage for a remote Dorian host.
type HostMetrics struct {
	CPUPercent       float64  `json:"cpuPercent"`
	MemoryUsedBytes  int64    `json:"memoryUsedBytes"`
	MemoryTotalBytes int64    `json:"memoryTotalBytes"`
	DiskUsedBytes    int64    `json:"diskUsedBytes"`
	DiskTotalBytes   int64    `json:"diskTotalBytes"`
	SwapUsedBytes    int64    `json:"swapUsedBytes"`
	SwapTotalBytes   int64    `json:"swapTotalBytes"`
	Load1            float64  `json:"load1"`
	Load5            float64  `json:"load5"`
	Load15           float64  `json:"load15"`
	UptimeSeconds    int64    `json:"uptimeSeconds"`
	CPUCores         int      `json:"cpuCores"`
	TemperatureC     *float64 `json:"temperatureC,omitempty"`
	TemperatureLabel string   `json:"temperatureLabel,omitempty"`
	NetRxBytesPerSec int64    `json:"netRxBytesPerSec"`
	NetTxBytesPerSec int64    `json:"netTxBytesPerSec"`
	NetLinkMbps      *int     `json:"netLinkMbps,omitempty"`
	NetInterface     string   `json:"netInterface,omitempty"`
	Hostname         string   `json:"hostname,omitempty"`
	Kernel           string   `json:"kernel,omitempty"`
}

const hostMetricsScript = `
read -r _ user nice system idle iowait irq softirq steal _rest < /proc/stat
cpu_total=$((user+nice+system+idle+iowait+irq+softirq+steal))
cpu_idle=$idle

iface=$(ip -o route show default 2>/dev/null | awk 'NR==1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')
if [ -z "$iface" ]; then
  iface=$(awk 'NR > 2 {
    name = $1
    gsub(":", "", name)
    if (name != "lo" && name !~ /^(docker|veth|br-|virbr|cni|flannel|cali|tunl)/) { print name; exit }
  }' /proc/net/dev)
fi
if [ -z "$iface" ]; then
  iface=$(awk 'NR > 2 { name = $1; gsub(":", "", name); if (name != "lo") { print name; exit } }' /proc/net/dev)
fi

read_net_bytes() {
  awk -v iface="$1" 'NR > 2 {
    name = $1
    gsub(":", "", name)
    if (name == iface) { printf "%s %s\n", $2, $10; found = 1; exit }
  }
  END { if (!found) print "0 0" }' /proc/net/dev
}
set -- $(read_net_bytes "$iface")
rx1=${1:-0}
tx1=${2:-0}

sleep 1

read -r _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 _rest2 < /proc/stat
cpu_total2=$((user2+nice2+system2+idle2+iowait2+irq2+softirq2+steal2))
cpu_idle2=$idle2
total_diff=$((cpu_total2-cpu_total))
idle_diff=$((cpu_idle2-cpu_idle))
if [ "$total_diff" -gt 0 ]; then
  cpu_pct=$(awk "BEGIN {printf \"%.1f\", (($total_diff-$idle_diff)*100)/$total_diff}")
else
  cpu_pct="0.0"
fi

set -- $(read_net_bytes "$iface")
rx2=${1:-0}
tx2=${2:-0}
rx_bps=$((rx2 - rx1))
tx_bps=$((tx2 - tx1))
if [ "$rx_bps" -lt 0 ]; then rx_bps=0; fi
if [ "$tx_bps" -lt 0 ]; then tx_bps=0; fi

link_mbps=""
if [ -n "$iface" ] && [ -r "/sys/class/net/$iface/speed" ]; then
  link_mbps=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || true)
  case "$link_mbps" in
    ''|-*|0) link_mbps="" ;;
  esac
fi

mem_total=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
mem_avail=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
mem_used=$((mem_total-mem_avail))
swap_total=$(awk '/SwapTotal:/ {print $2}' /proc/meminfo)
swap_free=$(awk '/SwapFree:/ {print $2}' /proc/meminfo)
swap_used=$((swap_total-swap_free))
if [ "$swap_used" -lt 0 ]; then swap_used=0; fi
disk_used=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $3}')
disk_total=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $2}')

read -r load1 load5 load15 _restload < /proc/loadavg
uptime_s=$(awk '{ printf "%d", $1 }' /proc/uptime)
cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo)
host_name=$(hostname -s 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || true)
kernel_ver=$(uname -r 2>/dev/null || true)
host_name=$(printf '%s' "$host_name" | tr -d '\n')
kernel_ver=$(printf '%s' "$kernel_ver" | tr -d '\n')

temp_pick=$(
  {
    for z in /sys/class/thermal/thermal_zone*; do
      [ -r "$z/temp" ] || continue
      type=$(cat "$z/type" 2>/dev/null || echo zone)
      val=$(cat "$z/temp" 2>/dev/null || true)
      printf '%s\t%s\n' "$type" "$val"
    done
    for mon in /sys/class/hwmon/hwmon*; do
      [ -d "$mon" ] || continue
      chip=$(cat "$mon/name" 2>/dev/null || echo hwmon)
      for input in "$mon"/temp*_input; do
        [ -r "$input" ] || continue
        base=${input%_input}
        label=$(cat "${base}_label" 2>/dev/null || true)
        val=$(cat "$input" 2>/dev/null || true)
        if [ -n "$label" ]; then
          printf '%s %s\t%s\n' "$chip" "$label" "$val"
        else
          printf '%s\t%s\n' "$chip" "$val"
        fi
      done
    done
  } | awk -F '\t' '
    function pref(s,    sl) {
      sl = tolower(s)
      return sl ~ /package/ || sl ~ /pkg/ || sl ~ /tdie/ || sl ~ /tctl/ || sl ~ /coretemp/ || sl ~ /k10temp/ || sl ~ /(^|[^a-z])cpu([^a-z]|$)/
    }
    {
      label = $1
      raw = $2
      if (raw !~ /^-?[0-9]+$/) next
      mc = raw + 0
      if (mc > -1000 && mc < 1000) mc = mc * 1000
      if (mc <= 0 || mc > 150000) next
      if (pref(label)) {
        if (best_pref == "" || mc > best_pref + 0) {
          best_pref = mc
          pref_label = label
        }
      }
      if (best_any == "" || mc > best_any + 0) {
        best_any = mc
        any_label = label
      }
    }
    END {
      if (best_pref != "") printf "%s\t%s\n", best_pref, pref_label
      else if (best_any != "") printf "%s\t%s\n", best_any, any_label
    }
  '
)
temp_mc=$(printf '%s' "$temp_pick" | awk -F '\t' 'NR==1 { print $1 }')
temp_label=$(printf '%s' "$temp_pick" | awk -F '\t' 'NR==1 { print $2 }' | tr -d '\n')

printf 'CPU=%s\nMEM_USED=%s\nMEM_TOTAL=%s\nDISK_USED=%s\nDISK_TOTAL=%s\nSWAP_USED=%s\nSWAP_TOTAL=%s\nLOAD1=%s\nLOAD5=%s\nLOAD15=%s\nUPTIME=%s\nCORES=%s\nHOSTNAME=%s\nKERNEL=%s\nNET_IFACE=%s\nNET_RX_BPS=%s\nNET_TX_BPS=%s\nNET_LINK_MBPS=%s\nTEMP_MC=%s\nTEMP_LABEL=%s\n' \
  "$cpu_pct" "$mem_used" "$mem_total" "$disk_used" "$disk_total" \
  "$swap_used" "$swap_total" "$load1" "$load5" "$load15" "$uptime_s" "$cores" \
  "$host_name" "$kernel_ver" "$iface" "$rx_bps" "$tx_bps" "$link_mbps" \
  "$temp_mc" "$temp_label"
`

func parseHostMetricsOutput(raw string) (HostMetrics, error) {
	values := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		values[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}

	cpu, err := strconv.ParseFloat(values["CPU"], 64)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse cpu: %w", err)
	}
	memUsed, err := parseMetricBytes(values["MEM_USED"], true)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse memory used: %w", err)
	}
	memTotal, err := parseMetricBytes(values["MEM_TOTAL"], true)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse memory total: %w", err)
	}
	diskUsed, err := parseMetricBytes(values["DISK_USED"], false)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse disk used: %w", err)
	}
	diskTotal, err := parseMetricBytes(values["DISK_TOTAL"], false)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("parse disk total: %w", err)
	}

	swapUsed, _ := parseMetricBytes(values["SWAP_USED"], true)
	swapTotal, _ := parseMetricBytes(values["SWAP_TOTAL"], true)
	if swapUsed < 0 {
		swapUsed = 0
	}
	if swapTotal < 0 {
		swapTotal = 0
	}
	if swapUsed > swapTotal && swapTotal > 0 {
		swapUsed = swapTotal
	}

	load1 := parseOptionalFloat(values["LOAD1"])
	load5 := parseOptionalFloat(values["LOAD5"])
	load15 := parseOptionalFloat(values["LOAD15"])
	uptime := parseOptionalInt(values["UPTIME"])
	cores := int(parseOptionalInt(values["CORES"]))
	if cores < 0 {
		cores = 0
	}

	rxBps := parseOptionalInt(values["NET_RX_BPS"])
	txBps := parseOptionalInt(values["NET_TX_BPS"])
	if rxBps < 0 {
		rxBps = 0
	}
	if txBps < 0 {
		txBps = 0
	}

	var tempC *float64
	if mc := parseOptionalFloat(values["TEMP_MC"]); mc > 0 && mc <= 150000 {
		celsius := mc / 1000
		tempC = &celsius
	}

	var linkMbps *int
	if mbps := int(parseOptionalInt(values["NET_LINK_MBPS"])); mbps > 0 {
		linkMbps = &mbps
	}

	return HostMetrics{
		CPUPercent:       cpu,
		MemoryUsedBytes:  memUsed,
		MemoryTotalBytes: memTotal,
		DiskUsedBytes:    diskUsed,
		DiskTotalBytes:   diskTotal,
		SwapUsedBytes:    swapUsed,
		SwapTotalBytes:   swapTotal,
		Load1:            load1,
		Load5:            load5,
		Load15:           load15,
		UptimeSeconds:    uptime,
		CPUCores:         cores,
		TemperatureC:     tempC,
		TemperatureLabel: values["TEMP_LABEL"],
		NetRxBytesPerSec: rxBps,
		NetTxBytesPerSec: txBps,
		NetLinkMbps:      linkMbps,
		NetInterface:     values["NET_IFACE"],
		Hostname:         values["HOSTNAME"],
		Kernel:           values["KERNEL"],
	}, nil
}

func parseOptionalFloat(raw string) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return value
}

func parseOptionalInt(raw string) int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0
	}
	return value
}

func parseMetricBytes(raw string, fromKib bool) (int64, error) {
	value, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		return 0, err
	}
	if fromKib {
		return value * 1024, nil
	}
	return value, nil
}

// ProbeHostMetrics SSHes to the target and reads CPU, memory, disk, network, and thermal state.
func ProbeHostMetrics(ctx context.Context, target SSHTarget) (HostMetrics, error) {
	client, err := dialSSH(ctx, target)
	if err != nil {
		return HostMetrics{}, err
	}
	defer client.Close()

	out, err := runRemoteScript(client, hostMetricsScript)
	if err != nil {
		return HostMetrics{}, fmt.Errorf("probe host metrics: %w", err)
	}
	return parseHostMetricsOutput(string(out))
}
