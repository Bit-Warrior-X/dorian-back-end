package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafBlacklistRule struct {
	ID          int64  `json:"id"`
	WafRuleID    int64  `json:"wafRuleId"`
	IPs         string `json:"ips"`
	URL         string `json:"url"`
	Method      string `json:"method"`
	Behavior    string `json:"behavior"`
	Description string `json:"description"`
}

type WafBlacklistInput struct {
	IPs         string
	URL         string
	Method      string
	Behavior    string
	Description string
}

type WafBlacklistStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafBlacklistRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafBlacklistInput) (WafBlacklistRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafBlacklistInput) (WafBlacklistRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafBlacklistStore struct {
	db *sql.DB
}

func NewWafBlacklistStore(db *sql.DB) WafBlacklistStore {
	return &wafBlacklistStore{db: db}
}

func (store *wafBlacklistStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafBlacklistRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, black_ip_list, url, method, behavior, description
		FROM waf_blacklist
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafBlacklistRule
	for rows.Next() {
		var rule WafBlacklistRule
		var description sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.IPs,
			&rule.URL,
			&rule.Method,
			&rule.Behavior,
			&description,
		); err != nil {
			return nil, err
		}
		rule.Description = nullStringValue(description)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafBlacklistStore) Create(ctx context.Context, wafRuleID int64, input WafBlacklistInput) (WafBlacklistRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_blacklist (waf_rule_id, black_ip_list, url, method, behavior, description)
		VALUES (?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.IPs,
		input.URL,
		input.Method,
		input.Behavior,
		nullableServerString(input.Description),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafBlacklistRule{}, errNotFound
		}
		return WafBlacklistRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafBlacklistRule{}, err
	}

	return WafBlacklistRule{
		ID:          id,
		WafRuleID:    wafRuleID,
		IPs:         input.IPs,
		URL:         input.URL,
		Method:      input.Method,
		Behavior:    input.Behavior,
		Description: input.Description,
	}, nil
}

func (store *wafBlacklistStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafBlacklistInput) (WafBlacklistRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_blacklist
		SET black_ip_list = ?, url = ?, method = ?, behavior = ?, description = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.IPs,
		input.URL,
		input.Method,
		input.Behavior,
		nullableServerString(input.Description),
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafBlacklistRule{}, errNotFound
		}
		return WafBlacklistRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafBlacklistRule{}, err
	}
	if affected == 0 {
		return WafBlacklistRule{}, errNotFound
	}

	return WafBlacklistRule{
		ID:          ruleID,
		WafRuleID:    wafRuleID,
		IPs:         input.IPs,
		URL:         input.URL,
		Method:      input.Method,
		Behavior:    input.Behavior,
		Description: input.Description,
	}, nil
}

func (store *wafBlacklistStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_blacklist WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafBlacklistStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_blacklist WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

