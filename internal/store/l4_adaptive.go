package store

import (
	"encoding/json"
	"strings"
)

// l4FirewallExtra is persisted in l4_ddos_defense.firewall_extra (JSON).
// Classic flood columns stay in relational fields; adaptive Sparta keys live here.
type l4FirewallExtra struct {
	PreferAdaptive       *bool             `json:"preferAdaptive,omitempty"`
	EnforceDropInvalid   *bool             `json:"enforceDropInvalid,omitempty"`
	DetectionLevel       *int              `json:"detectionLevel,omitempty"`
	AlertHoldWindows     *int              `json:"alertHoldWindows,omitempty"`
	QuietClearWindows    *int              `json:"quietClearWindows,omitempty"`
	ConfirmWindows       *int              `json:"confirmWindows,omitempty"`
	ExitWindows          *int              `json:"exitWindows,omitempty"`
	CooldownSeconds       *int              `json:"cooldownSeconds,omitempty"`
	EscalateAfterWindows *int              `json:"escalateAfterWindows,omitempty"`
	BlockInitialSeconds  *int              `json:"blockInitialSeconds,omitempty"`
	BlockMaxSeconds      *int              `json:"blockMaxSeconds,omitempty"`
	BaselineK            *int              `json:"baselineK,omitempty"`
	BaselineM            *int              `json:"baselineM,omitempty"`
	LearningDays         *int              `json:"learningDays,omitempty"`
	ServiceHttp3         *bool             `json:"serviceHttp3,omitempty"`
	ServiceDns           *bool             `json:"serviceDns,omitempty"`
	ServiceGreTunnels    *bool             `json:"serviceGreTunnels,omitempty"`
	Raw                  map[string]string `json:"raw,omitempty"`
}

func boolPtr(v bool) *bool { return &v }
func intPtr(v int) *int    { return &v }

func (cfg *L4Config) encodeFirewallExtra() (string, error) {
	if cfg == nil {
		return "", nil
	}
	extra := l4FirewallExtra{
		PreferAdaptive:       boolPtr(cfg.PreferAdaptive),
		EnforceDropInvalid:   boolPtr(cfg.EnforceDropInvalid),
		DetectionLevel:       intPtr(cfg.DetectionLevel),
		AlertHoldWindows:     intPtr(cfg.AlertHoldWindows),
		QuietClearWindows:    intPtr(cfg.QuietClearWindows),
		ConfirmWindows:       intPtr(cfg.ConfirmWindows),
		ExitWindows:          intPtr(cfg.ExitWindows),
		CooldownSeconds:       intPtr(cfg.CooldownSeconds),
		EscalateAfterWindows: intPtr(cfg.EscalateAfterWindows),
		BlockInitialSeconds:  intPtr(cfg.BlockInitialSeconds),
		BlockMaxSeconds:      intPtr(cfg.BlockMaxSeconds),
		BaselineK:            intPtr(cfg.BaselineK),
		BaselineM:            intPtr(cfg.BaselineM),
		LearningDays:         intPtr(cfg.LearningDays),
		ServiceHttp3:         boolPtr(cfg.ServiceHttp3),
		ServiceDns:           boolPtr(cfg.ServiceDns),
		ServiceGreTunnels:    boolPtr(cfg.ServiceGreTunnels),
		Raw:                  cfg.FirewallConfig,
	}
	raw, err := json.Marshal(extra)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (cfg *L4Config) decodeFirewallExtra(raw string) {
	if cfg == nil {
		return
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	var extra l4FirewallExtra
	if err := json.Unmarshal([]byte(raw), &extra); err != nil {
		return
	}
	if extra.PreferAdaptive != nil {
		cfg.PreferAdaptive = *extra.PreferAdaptive
	}
	if extra.EnforceDropInvalid != nil {
		cfg.EnforceDropInvalid = *extra.EnforceDropInvalid
	}
	if extra.DetectionLevel != nil {
		cfg.DetectionLevel = *extra.DetectionLevel
	}
	if extra.AlertHoldWindows != nil {
		cfg.AlertHoldWindows = *extra.AlertHoldWindows
	}
	if extra.QuietClearWindows != nil {
		cfg.QuietClearWindows = *extra.QuietClearWindows
	}
	if extra.ConfirmWindows != nil {
		cfg.ConfirmWindows = *extra.ConfirmWindows
	}
	if extra.ExitWindows != nil {
		cfg.ExitWindows = *extra.ExitWindows
	}
	if extra.CooldownSeconds != nil {
		cfg.CooldownSeconds = *extra.CooldownSeconds
	}
	if extra.EscalateAfterWindows != nil {
		cfg.EscalateAfterWindows = *extra.EscalateAfterWindows
	}
	if extra.BlockInitialSeconds != nil {
		cfg.BlockInitialSeconds = *extra.BlockInitialSeconds
	}
	if extra.BlockMaxSeconds != nil {
		cfg.BlockMaxSeconds = *extra.BlockMaxSeconds
	}
	if extra.BaselineK != nil {
		cfg.BaselineK = *extra.BaselineK
	}
	if extra.BaselineM != nil {
		cfg.BaselineM = *extra.BaselineM
	}
	if extra.LearningDays != nil {
		cfg.LearningDays = *extra.LearningDays
	}
	if extra.ServiceHttp3 != nil {
		cfg.ServiceHttp3 = *extra.ServiceHttp3
	}
	if extra.ServiceDns != nil {
		cfg.ServiceDns = *extra.ServiceDns
	}
	if extra.ServiceGreTunnels != nil {
		cfg.ServiceGreTunnels = *extra.ServiceGreTunnels
	}
	if len(extra.Raw) > 0 {
		cfg.FirewallConfig = extra.Raw
	}
}

// ApplyFirewallConfigRaw merges a full edge firewall_config map into typed fields
// and keeps the raw snapshot for round-trip fidelity.
func ApplyFirewallConfigRaw(cfg *L4Config, raw map[string]string) {
	if cfg == nil || len(raw) == 0 {
		return
	}
	merged := make(map[string]string, len(cfg.FirewallConfig)+len(raw))
	for k, v := range cfg.FirewallConfig {
		merged[k] = v
	}
	for k, v := range raw {
		merged[k] = v
	}
	cfg.FirewallConfig = merged

	get := func(keys ...string) (string, bool) {
		for _, key := range keys {
			if value, ok := raw[key]; ok {
				return strings.TrimSpace(value), true
			}
			for existing, value := range raw {
				if strings.EqualFold(existing, key) {
					return strings.TrimSpace(value), true
				}
			}
		}
		return "", false
	}
	parseBool := func(value string) (bool, bool) {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on", "enable", "enabled":
			return true, true
		case "0", "false", "no", "off", "disable", "disabled":
			return false, true
		default:
			return false, false
		}
	}
	parseInt := func(value string) (int, bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return 0, false
		}
		n := 0
		for _, r := range value {
			if r < '0' || r > '9' {
				return 0, false
			}
			n = n*10 + int(r-'0')
		}
		return n, true
	}
	setBool := func(dst *bool, keys ...string) {
		if value, ok := get(keys...); ok {
			if parsed, ok := parseBool(value); ok {
				*dst = parsed
			}
		}
	}
	setInt := func(dst *int, keys ...string) {
		if value, ok := get(keys...); ok {
			if parsed, ok := parseInt(value); ok {
				*dst = parsed
			}
		}
	}

	setBool(&cfg.PreferAdaptive, "prefer_adaptive", "preferAdaptive")
	setBool(&cfg.EnforceDropInvalid, "enforce_drop_invalid", "enforceDropInvalid")
	setInt(&cfg.DetectionLevel, "detection_level", "detectionLevel")
	setInt(&cfg.AlertHoldWindows, "alert_hold_windows", "alertHoldWindows")
	setInt(&cfg.QuietClearWindows, "quiet_clear_windows", "quietClearWindows")
	setInt(&cfg.ConfirmWindows, "confirm_windows", "confirmWindows")
	setInt(&cfg.ExitWindows, "exit_windows", "exitWindows")
	setInt(&cfg.CooldownSeconds, "cooldown_seconds", "cooldownSeconds")
	setInt(&cfg.EscalateAfterWindows, "escalate_after_windows", "escalateAfterWindows")
	setInt(&cfg.BlockInitialSeconds, "block_initial_seconds", "blockInitialSeconds")
	setInt(&cfg.BlockMaxSeconds, "block_max_seconds", "blockMaxSeconds")
	setInt(&cfg.BaselineK, "baseline_k", "baselineK")
	setInt(&cfg.BaselineM, "baseline_m", "baselineM")
	setInt(&cfg.LearningDays, "learning_days", "learningDays")
	setBool(&cfg.ServiceHttp3, "service_http3", "serviceHttp3")
	setBool(&cfg.ServiceDns, "service_dns", "serviceDns")
	setBool(&cfg.ServiceGreTunnels, "service_gre_tunnels", "serviceGreTunnels")

	if cfg.DetectionLevel > 0 {
		cfg.Sensitivity = SensitivityFromDetectionLevel(cfg.DetectionLevel)
	}
	if cfg.PreferAdaptive {
		if cfg.DetectionLevel <= 0 {
			cfg.DetectionLevel = 5
		}
		if cfg.BlockInitialSeconds <= 0 && cfg.BlackIPDuration > 0 {
			cfg.BlockInitialSeconds = cfg.BlackIPDuration
			if cfg.BlockInitialSeconds > 600 {
				cfg.BlockInitialSeconds = 60
			}
		}
		if cfg.BlockMaxSeconds <= 0 {
			if cfg.BlackIPDuration > 0 {
				cfg.BlockMaxSeconds = cfg.BlackIPDuration
			} else {
				cfg.BlockMaxSeconds = 3600
			}
		}
		if cfg.AlertHoldWindows <= 0 {
			cfg.AlertHoldWindows = 5
		}
	}
}

// SensitivityFromDetectionLevel maps adaptive 1..10 onto the legacy Low/Medium/High enum.
func SensitivityFromDetectionLevel(level int) string {
	switch {
	case level <= 3:
		return "Low"
	case level <= 6:
		return "Medium"
	default:
		return "High"
	}
}

// DetectionLevelFromSensitivity maps legacy sensitivity onto a detection level.
func DetectionLevelFromSensitivity(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return 3
	case "high":
		return 8
	default:
		return 5
	}
}

// NormalizeL4AdaptiveDefaults fills safe defaults before push/persist.
func NormalizeL4AdaptiveDefaults(cfg *L4Config) {
	if cfg == nil {
		return
	}
	if cfg.DetectionLevel <= 0 {
		if cfg.PreferAdaptive {
			cfg.DetectionLevel = DetectionLevelFromSensitivity(cfg.Sensitivity)
		}
	} else if cfg.DetectionLevel > 10 {
		cfg.DetectionLevel = 10
	}
	if cfg.PreferAdaptive {
		if cfg.BlockInitialSeconds <= 0 {
			cfg.BlockInitialSeconds = 60
		}
		if cfg.BlockMaxSeconds <= 0 {
			cfg.BlockMaxSeconds = 3600
		}
		if cfg.BlockMaxSeconds < cfg.BlockInitialSeconds {
			cfg.BlockMaxSeconds = cfg.BlockInitialSeconds
		}
		if cfg.AlertHoldWindows <= 0 {
			cfg.AlertHoldWindows = 5
		}
		if cfg.Sensitivity == "" {
			cfg.Sensitivity = SensitivityFromDetectionLevel(cfg.DetectionLevel)
		}
	}
}
