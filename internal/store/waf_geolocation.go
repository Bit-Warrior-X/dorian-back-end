package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafGeoRule struct {
	ID        int64  `json:"id"`
	WafRuleID  int64  `json:"wafRuleId"`
	Country   string `json:"country"`
	URL       string `json:"url"`
	Behavior  string `json:"behavior"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

type WafGeoInput struct {
	Country   string
	URL       string
	Behavior  string
	Operation string
	Status    string
}

type WafGeoStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafGeoRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafGeoInput) (WafGeoRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafGeoInput) (WafGeoRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafGeoStore struct {
	db *sql.DB
}

func NewWafGeoStore(db *sql.DB) WafGeoStore {
	return &wafGeoStore{db: db}
}

func (store *wafGeoStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafGeoRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, country, url, behavior, operation, status
		FROM waf_geolocation
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafGeoRule
	for rows.Next() {
		var rule WafGeoRule
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.Country,
			&rule.URL,
			&rule.Behavior,
			&rule.Operation,
			&rule.Status,
		); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafGeoStore) Create(ctx context.Context, wafRuleID int64, input WafGeoInput) (WafGeoRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_geolocation (waf_rule_id, country, url, behavior, operation, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.Country,
		input.URL,
		input.Behavior,
		input.Operation,
		input.Status,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafGeoRule{}, errNotFound
		}
		return WafGeoRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafGeoRule{}, err
	}

	return WafGeoRule{
		ID:        id,
		WafRuleID:  wafRuleID,
		Country:   input.Country,
		URL:       input.URL,
		Behavior:  input.Behavior,
		Operation: input.Operation,
		Status:    input.Status,
	}, nil
}

func (store *wafGeoStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafGeoInput) (WafGeoRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_geolocation
		SET country = ?, url = ?, behavior = ?, operation = ?, status = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.Country,
		input.URL,
		input.Behavior,
		input.Operation,
		input.Status,
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafGeoRule{}, errNotFound
		}
		return WafGeoRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafGeoRule{}, err
	}
	if affected == 0 {
		return WafGeoRule{}, errNotFound
	}

	return WafGeoRule{
		ID:        ruleID,
		WafRuleID:  wafRuleID,
		Country:   input.Country,
		URL:       input.URL,
		Behavior:  input.Behavior,
		Operation: input.Operation,
		Status:    input.Status,
	}, nil
}

func (store *wafGeoStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_geolocation WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafGeoStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
	ids := uniqueInt64(ruleIDs)
	if len(ids) == 0 {
		return nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+1)
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	args = append(args, wafRuleID)

	query := "DELETE FROM waf_geolocation WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
