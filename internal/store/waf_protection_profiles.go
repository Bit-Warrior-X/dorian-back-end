package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Stable display names for the built-in protection profiles (predefined waf_rule rows).
const (
	ProtectionProfileOff       = "Protection — Off"
	ProtectionProfileEssential = "Protection — Essential"
	ProtectionProfileStandard  = "Protection — Standard"
	ProtectionProfileStrict    = "Protection — Strict"
)

const (
	ProtectionKeyOff       = "off"
	ProtectionKeyEssential = "essential"
	ProtectionKeyStandard  = "standard"
	ProtectionKeyStrict    = "strict"
)

// ProtectionProfile is a curated predefined WAF pack customers pick on a site.
type ProtectionProfile struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
	WafRuleID   int64  `json:"wafRuleId"`
	Role        string `json:"role"`
}

var protectionProfileDefs = []struct {
	Key         string
	Name        string
	Description string
}{
	{ProtectionKeyOff, ProtectionProfileOff, "Pass traffic with no WAF rules. Use while debugging or for trusted internal sites."},
	{ProtectionKeyEssential, ProtectionProfileEssential, "Basic abuse cover: flood limits, 404 scanner throttle, and known scraper user-agents."},
	{ProtectionKeyStandard, ProtectionProfileStandard, "Recommended default. Essential plus sensitive-path limits and high-risk GEO deny."},
	{ProtectionKeyStrict, ProtectionProfileStrict, "Under attack or high-risk. Tighter thresholds, Challenge / Drop+Block, and stricter GEO and UA filters."},
}

// ProtectionProfileName returns the stable waf_rule.name for a profile key.
func ProtectionProfileName(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case ProtectionKeyOff:
		return ProtectionProfileOff
	case ProtectionKeyEssential:
		return ProtectionProfileEssential
	case ProtectionKeyStandard:
		return ProtectionProfileStandard
	case ProtectionKeyStrict:
		return ProtectionProfileStrict
	default:
		return ""
	}
}

// ProtectionProfileKeyFromName maps a waf_rule.name back to a profile key.
func ProtectionProfileKeyFromName(name string) string {
	switch strings.TrimSpace(name) {
	case ProtectionProfileOff:
		return ProtectionKeyOff
	case ProtectionProfileEssential:
		return ProtectionKeyEssential
	case ProtectionProfileStandard:
		return ProtectionKeyStandard
	case ProtectionProfileStrict:
		return ProtectionKeyStrict
	default:
		return ""
	}
}

// EnsureProtectionProfiles creates the four built-in predefined packs once (idempotent by name).
func EnsureProtectionProfiles(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("database is required")
	}
	for _, def := range protectionProfileDefs {
		id, err := ensureProtectionPack(ctx, db, def.Name)
		if err != nil {
			return err
		}
		if err := seedProtectionPackRules(ctx, db, def.Key, id); err != nil {
			return fmt.Errorf("seed %s: %w", def.Key, err)
		}
		if err := repairProtectionPackRules(ctx, db, id); err != nil {
			return fmt.Errorf("repair %s: %w", def.Key, err)
		}
	}
	return nil
}

// repairProtectionPackRules removes known-bad seed rows that overblock legitimate traffic.
func repairProtectionPackRules(ctx context.Context, db *sql.DB, wafRuleID int64) error {
	// Empty User-Agent Equals matches every request on Athens.
	if _, err := db.ExecContext(ctx, `
		DELETE FROM waf_useragent
		WHERE waf_rule_id = ? AND `+"`match`"+` = 'Equals' AND user_agent = ''`, wafRuleID); err != nil {
		return err
	}
	// User-Agent anti-header seeds with "" or ".+" overblock (values are not full regex).
	if _, err := db.ExecContext(ctx, `
		DELETE FROM waf_antiheader
		WHERE waf_rule_id = ?
		  AND header = 'User-Agent'
		  AND (
		    (value = '' AND block_mode = 'If match')
		    OR (value = '.+' AND block_mode = 'If not match')
		  )`, wafRuleID); err != nil {
		return err
	}
	return nil
}

// LookupProtectionProfileID returns the waf_rule id for a profile key, or 0 if missing.
func LookupProtectionProfileID(ctx context.Context, db *sql.DB, key string) (int64, error) {
	name := ProtectionProfileName(key)
	if name == "" {
		return 0, fmt.Errorf("unknown protection profile %q", key)
	}
	var id int64
	err := db.QueryRowContext(ctx, `
		SELECT id FROM waf_rule WHERE name = ? AND role = 'predefined' LIMIT 1`, name).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return id, err
}

// ListProtectionProfiles returns the built-in profiles with current waf_rule ids.
func ListProtectionProfiles(ctx context.Context, db *sql.DB) ([]ProtectionProfile, error) {
	out := make([]ProtectionProfile, 0, len(protectionProfileDefs))
	for _, def := range protectionProfileDefs {
		var id sql.NullInt64
		err := db.QueryRowContext(ctx, `
			SELECT id FROM waf_rule WHERE name = ? AND role = 'predefined' LIMIT 1`, def.Name).Scan(&id)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		item := ProtectionProfile{
			Key:         def.Key,
			Name:        def.Name,
			Description: def.Description,
			Role:        "predefined",
		}
		if id.Valid {
			item.WafRuleID = id.Int64
		}
		out = append(out, item)
	}
	return out, nil
}

// ApplyDefaultProtectionWafID sets Standard when wafId is omitted on site create.
func ApplyDefaultProtectionWafID(ctx context.Context, db *sql.DB, input *SiteInput) error {
	if input == nil || (input.WafID != nil && *input.WafID > 0) {
		return nil
	}
	id, err := LookupProtectionProfileID(ctx, db, ProtectionKeyStandard)
	if err != nil {
		return err
	}
	if id <= 0 {
		return nil
	}
	input.WafID = &id
	return nil
}

func ensureProtectionPack(ctx context.Context, db *sql.DB, name string) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		SELECT id FROM waf_rule WHERE name = ? AND role = 'predefined' LIMIT 1`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	result, err := db.ExecContext(ctx, `
		INSERT INTO waf_rule (name, role) VALUES (?, 'predefined')`, name)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func seedProtectionPackRules(ctx context.Context, db *sql.DB, key string, wafRuleID int64) error {
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT (
			(SELECT COUNT(*) FROM waf_anticc WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_secondfreqlimit WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_responsefreq WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_useragent WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_geolocation WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_antiheader WHERE waf_rule_id = ?) +
			(SELECT COUNT(*) FROM waf_intervalfreqlimit WHERE waf_rule_id = ?)
		)`, wafRuleID, wafRuleID, wafRuleID, wafRuleID, wafRuleID, wafRuleID, wafRuleID).Scan(&count); err != nil {
		return err
	}
	if count > 0 || key == ProtectionKeyOff {
		return nil
	}

	switch key {
	case ProtectionKeyEssential:
		return seedEssentialRules(ctx, db, wafRuleID)
	case ProtectionKeyStandard:
		if err := seedEssentialRules(ctx, db, wafRuleID); err != nil {
			return err
		}
		return seedStandardExtras(ctx, db, wafRuleID)
	case ProtectionKeyStrict:
		return seedStrictRules(ctx, db, wafRuleID)
	default:
		return nil
	}
}

func seedEssentialRules(ctx context.Context, db *sql.DB, wafRuleID int64) error {
	if err := insertAntiCc(ctx, db, wafRuleID, "/*", "GET, POST", 200, 10, "Challenge", "Deny"); err != nil {
		return err
	}
	if err := insertSecond(ctx, db, wafRuleID, "/*", 50, 20, "Deny"); err != nil {
		return err
	}
	if err := insertResponse(ctx, db, wafRuleID, "/*", "404", 60, 30, "Deny"); err != nil {
		return err
	}
	// Do not seed User-Agent Equals "" — Athens treats it as matching every request.
	for _, ua := range []string{"sqlmap", "nikto", "masscan", "zgrab", "scrapy", "HTTrack"} {
		if err := insertUserAgent(ctx, db, wafRuleID, "/*", ua, "Contains", "Deny"); err != nil {
			return err
		}
	}
	return nil
}

func seedStandardExtras(ctx context.Context, db *sql.DB, wafRuleID int64) error {
	for _, path := range []string{"/login", "/api", "/admin"} {
		if err := insertAntiCc(ctx, db, wafRuleID, path, "GET, POST", 40, 10, "Challenge", "Deny"); err != nil {
			return err
		}
	}
	if err := insertInterval(ctx, db, wafRuleID, "/login", 60, 30, "Deny"); err != nil {
		return err
	}
	// Skip anti-header empty-UA checks: Athens does not treat values as regex, so
	// patterns like ".+" / "" overblock legitimate browsers.
	return insertGeo(ctx, db, wafRuleID, "China, Russia, Iran, North Korea", "/*", "Deny", "BLACK")
}

func seedStrictRules(ctx context.Context, db *sql.DB, wafRuleID int64) error {
	if err := insertAntiCc(ctx, db, wafRuleID, "/*", "GET, POST", 80, 5, "Challenge", "Drop+Block"); err != nil {
		return err
	}
	if err := insertSecond(ctx, db, wafRuleID, "/*", 20, 5, "Drop+Block"); err != nil {
		return err
	}
	if err := insertResponse(ctx, db, wafRuleID, "/*", "404", 60, 15, "Drop+Block"); err != nil {
		return err
	}
	if err := insertResponse(ctx, db, wafRuleID, "/*", "401", 60, 20, "Drop+Block"); err != nil {
		return err
	}
	for _, path := range []string{"/login", "/api", "/admin"} {
		if err := insertAntiCc(ctx, db, wafRuleID, path, "GET, POST", 20, 5, "Challenge", "Drop+Block"); err != nil {
			return err
		}
		if err := insertInterval(ctx, db, wafRuleID, path, 60, 20, "Drop+Block"); err != nil {
			return err
		}
	}
	for _, ua := range []string{"sqlmap", "nikto", "masscan", "zgrab", "scrapy", "HTTrack", "python-requests", "Go-http-client", "curl"} {
		if err := insertUserAgent(ctx, db, wafRuleID, "/*", ua, "Contains", "Drop+Block"); err != nil {
			return err
		}
	}
	return insertGeo(ctx, db, wafRuleID, "China, Russia, Iran, North Korea", "/*", "Drop+Block", "BLACK")
}

func insertAntiCc(ctx context.Context, db *sql.DB, wafRuleID int64, url, method string, threshold, window int, action, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_anticc (waf_rule_id, url, method, threshold, `+"`window`"+`, action, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, method, threshold, window, action, behavior)
	return err
}

func insertSecond(ctx context.Context, db *sql.DB, wafRuleID int64, url string, count, burst int, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_secondfreqlimit (waf_rule_id, url, request_count, burst, behavior, status)
		VALUES (?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, count, burst, behavior)
	return err
}

func insertInterval(ctx context.Context, db *sql.DB, wafRuleID int64, url string, timeSec, count int, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_intervalfreqlimit (waf_rule_id, url, time, request_count, behavior, status)
		VALUES (?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, timeSec, count, behavior)
	return err
}

func insertResponse(ctx context.Context, db *sql.DB, wafRuleID int64, url, code string, timeSec, count int, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_responsefreq (waf_rule_id, url, response_code, time, response_count, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, code, timeSec, count, behavior)
	return err
}

func insertUserAgent(ctx context.Context, db *sql.DB, wafRuleID int64, url, ua, match, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_useragent (waf_rule_id, url, user_agent, `+"`match`"+`, behavior, status)
		VALUES (?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, ua, match, behavior)
	return err
}

func insertAntiHeader(ctx context.Context, db *sql.DB, wafRuleID int64, url, header, value, blockMode, behavior string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_antiheader (waf_rule_id, url, header, value, block_mode, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, url, header, value, blockMode, behavior)
	return err
}

func insertGeo(ctx context.Context, db *sql.DB, wafRuleID int64, country, url, behavior, operation string) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO waf_geolocation (waf_rule_id, country, url, behavior, operation, status)
		VALUES (?, ?, ?, ?, ?, 'ENABLE')`,
		wafRuleID, country, url, behavior, operation)
	return err
}
