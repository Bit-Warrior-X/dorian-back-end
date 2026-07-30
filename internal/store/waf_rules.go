package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

type WafRule struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"createdAt"`
	SiteCount int       `json:"siteCount"`
	RuleCount int       `json:"ruleCount"`
}

type WafRuleInput struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

type WafRuleStore interface {
	List(ctx context.Context) ([]WafRule, error)
	ListByRole(ctx context.Context, role string) ([]WafRule, error)
	Get(ctx context.Context, id int64) (WafRule, error)
	Create(ctx context.Context, input WafRuleInput) (WafRule, error)
	Update(ctx context.Context, id int64, input WafRuleInput) (WafRule, error)
	Delete(ctx context.Context, id int64) error
	Duplicate(ctx context.Context, sourceID int64, name string) (WafRule, error)
}

type wafRuleStore struct {
	db *sql.DB
}

func NewWafRuleStore(db *sql.DB) WafRuleStore {
	return &wafRuleStore{db: db}
}

const wafRuleCountSelectSQL = `(
	(SELECT COUNT(*) FROM waf_whitelist wl WHERE wl.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_blacklist bl WHERE bl.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_geolocation gl WHERE gl.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_anticc ac WHERE ac.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_antiheader ah WHERE ah.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_intervalfreqlimit ifl WHERE ifl.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_secondfreqlimit sfl WHERE sfl.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_responsefreq rf WHERE rf.waf_rule_id = wr.id) +
	(SELECT COUNT(*) FROM waf_useragent ua WHERE ua.waf_rule_id = wr.id)
)`

func (input WafRuleInput) Normalize() WafRuleInput {
	role := strings.ToLower(strings.TrimSpace(input.Role))
	if role != "predefined" {
		role = "custom"
	}
	return WafRuleInput{
		Name: strings.TrimSpace(input.Name),
		Role: role,
	}
}

func (store *wafRuleStore) List(ctx context.Context) ([]WafRule, error) {
	return store.ListByRole(ctx, "")
}

func (store *wafRuleStore) ListByRole(ctx context.Context, role string) ([]WafRule, error) {
	query := `
		SELECT wr.id, wr.name, wr.role, wr.created_at, COUNT(s.id) AS site_count, ` + wafRuleCountSelectSQL + ` AS rule_count
		FROM waf_rule wr
		LEFT JOIN sites s ON s.waf_id = wr.id`
	args := []any{}
	role = strings.ToLower(strings.TrimSpace(role))
	if role != "" {
		query += ` WHERE wr.role = ?`
		args = append(args, role)
	}
	query += `
		GROUP BY wr.id, wr.name, wr.role, wr.created_at`
	if role == "" {
		query += `
		ORDER BY CASE WHEN wr.role = 'predefined' THEN 0 ELSE 1 END, wr.created_at DESC`
	} else {
		query += `
		ORDER BY wr.created_at DESC`
	}

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafRule
	for rows.Next() {
		var item WafRule
		if err := rows.Scan(&item.ID, &item.Name, &item.Role, &item.CreatedAt, &item.SiteCount, &item.RuleCount); err != nil {
			return nil, err
		}
		rules = append(rules, item)
	}
	return rules, rows.Err()
}

func (store *wafRuleStore) Get(ctx context.Context, id int64) (WafRule, error) {
	var item WafRule
	row := store.db.QueryRowContext(ctx, `
		SELECT wr.id, wr.name, wr.role, wr.created_at, COUNT(s.id) AS site_count, `+wafRuleCountSelectSQL+` AS rule_count
		FROM waf_rule wr
		LEFT JOIN sites s ON s.waf_id = wr.id
		WHERE wr.id = ?
		GROUP BY wr.id, wr.name, wr.role, wr.created_at
		LIMIT 1`, id)
	if err := row.Scan(&item.ID, &item.Name, &item.Role, &item.CreatedAt, &item.SiteCount, &item.RuleCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WafRule{}, errNotFound
		}
		return WafRule{}, err
	}
	return item, nil
}

func (store *wafRuleStore) Create(ctx context.Context, input WafRuleInput) (WafRule, error) {
	input = input.Normalize()
	if input.Name == "" {
		return WafRule{}, errors.New("name is required")
	}
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_rule (name, role)
		VALUES (?, ?)`, input.Name, input.Role)
	if err != nil {
		return WafRule{}, err
	}
	id, err := result.LastInsertId()
	if err != nil {
		return WafRule{}, err
	}
	return store.Get(ctx, id)
}

func (store *wafRuleStore) Update(ctx context.Context, id int64, input WafRuleInput) (WafRule, error) {
	input = input.Normalize()
	if input.Name == "" {
		return WafRule{}, errors.New("name is required")
	}
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_rule
		SET name = ?, role = ?
		WHERE id = ?`, input.Name, input.Role, id)
	if err != nil {
		return WafRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafRule{}, err
	}
	if affected == 0 {
		return store.Get(ctx, id)
	}
	return store.Get(ctx, id)
}

func (store *wafRuleStore) Delete(ctx context.Context, id int64) error {
	var siteCount int
	if err := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM sites
		WHERE waf_id = ?`, id).Scan(&siteCount); err != nil {
		return err
	}
	if siteCount > 0 {
		return errors.New("waf rule is assigned to one or more sites")
	}

	result, err := store.db.ExecContext(ctx, `DELETE FROM waf_rule WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errNotFound
	}
	return nil
}

func (store *wafRuleStore) Duplicate(ctx context.Context, sourceID int64, name string) (WafRule, error) {
	source, err := store.Get(ctx, sourceID)
	if err != nil {
		return WafRule{}, err
	}
	if strings.ToLower(source.Role) != "predefined" {
		return WafRule{}, errors.New("only predefined waf rules can be duplicated")
	}

	copyName := strings.TrimSpace(name)
	if copyName == "" {
		return WafRule{}, errors.New("name is required")
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return WafRule{}, err
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx, `
		INSERT INTO waf_rule (name, role)
		VALUES (?, 'custom')`, copyName)
	if err != nil {
		return WafRule{}, err
	}
	newID, err := result.LastInsertId()
	if err != nil {
		return WafRule{}, err
	}

	if err := copyWafSubRules(ctx, tx, sourceID, newID); err != nil {
		return WafRule{}, err
	}

	if err := tx.Commit(); err != nil {
		return WafRule{}, err
	}
	return store.Get(ctx, newID)
}

func copyWafSubRules(ctx context.Context, tx *sql.Tx, sourceID, targetID int64) error {
	queries := []string{
		`INSERT INTO waf_whitelist (waf_rule_id, white_ip_list, url, method, description)
		 SELECT ?, white_ip_list, url, method, description FROM waf_whitelist WHERE waf_rule_id = ?`,
		`INSERT INTO waf_blacklist (waf_rule_id, black_ip_list, url, method, behavior, description)
		 SELECT ?, black_ip_list, url, method, behavior, description FROM waf_blacklist WHERE waf_rule_id = ?`,
		`INSERT INTO waf_geolocation (waf_rule_id, country, url, behavior, operation, status)
		 SELECT ?, country, url, behavior, operation, status FROM waf_geolocation WHERE waf_rule_id = ?`,
		`INSERT INTO waf_anticc (waf_rule_id, url, method, threshold, ` + "`window`" + `, action, behavior, status)
		 SELECT ?, url, method, threshold, ` + "`window`" + `, action, behavior, status FROM waf_anticc WHERE waf_rule_id = ?`,
		`INSERT INTO waf_antiheader (waf_rule_id, url, header, value, block_mode, behavior, status)
		 SELECT ?, url, header, value, block_mode, behavior, status FROM waf_antiheader WHERE waf_rule_id = ?`,
		`INSERT INTO waf_intervalfreqlimit (waf_rule_id, url, time, request_count, behavior, status)
		 SELECT ?, url, time, request_count, behavior, status FROM waf_intervalfreqlimit WHERE waf_rule_id = ?`,
		`INSERT INTO waf_secondfreqlimit (waf_rule_id, url, request_count, burst, behavior, status)
		 SELECT ?, url, request_count, burst, behavior, status FROM waf_secondfreqlimit WHERE waf_rule_id = ?`,
		`INSERT INTO waf_responsefreq (waf_rule_id, url, response_code, time, response_count, behavior, status)
		 SELECT ?, url, response_code, time, response_count, behavior, status FROM waf_responsefreq WHERE waf_rule_id = ?`,
		`INSERT INTO waf_useragent (waf_rule_id, url, user_agent, ` + "`match`" + `, behavior, status)
		 SELECT ?, url, user_agent, ` + "`match`" + `, behavior, status FROM waf_useragent WHERE waf_rule_id = ?`,
	}
	for _, query := range queries {
		if _, err := tx.ExecContext(ctx, query, targetID, sourceID); err != nil {
			return err
		}
	}
	return nil
}
