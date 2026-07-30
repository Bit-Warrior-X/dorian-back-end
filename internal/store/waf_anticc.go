package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafAntiCcRule struct {
	ID        int64  `json:"id"`
	WafRuleID  int64  `json:"wafRuleId"`
	URL       string `json:"url"`
	Method    string `json:"method"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window"`
	Action    string `json:"action"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type WafAntiCcInput struct {
	URL       string
	Method    string
	Threshold int
	Window    int
	Action    string
	Behavior  string
	Status    string
}

type WafAntiCcStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafAntiCcRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafAntiCcInput) (WafAntiCcRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafAntiCcInput) (WafAntiCcRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafAntiCcStore struct {
	db *sql.DB
}

func NewWafAntiCcStore(db *sql.DB) WafAntiCcStore {
	return &wafAntiCcStore{db: db}
}

func (store *wafAntiCcStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafAntiCcRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, url, method, threshold, ` + "`window`" + `, action, behavior, status
		FROM waf_anticc
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafAntiCcRule
	for rows.Next() {
		var rule WafAntiCcRule
		var threshold sql.NullInt64
		var window sql.NullInt64
		var action sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.URL,
			&rule.Method,
			&threshold,
			&window,
			&action,
			&rule.Behavior,
			&rule.Status,
		); err != nil {
			return nil, err
		}
		rule.Threshold = nullIntValue(threshold)
		rule.Window = nullIntValue(window)
		rule.Action = nullStringValue(action)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafAntiCcStore) Create(ctx context.Context, wafRuleID int64, input WafAntiCcInput) (WafAntiCcRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_anticc (waf_rule_id, url, method, threshold, ` + "`window`" + `, action, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.URL,
		input.Method,
		nullableInt(input.Threshold),
		nullableInt(input.Window),
		nullableServerString(input.Action),
		input.Behavior,
		input.Status,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafAntiCcRule{}, errNotFound
		}
		return WafAntiCcRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafAntiCcRule{}, err
	}

	return WafAntiCcRule{
		ID:        id,
		WafRuleID:  wafRuleID,
		URL:       input.URL,
		Method:    input.Method,
		Threshold: input.Threshold,
		Window:    input.Window,
		Action:    input.Action,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafAntiCcStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafAntiCcInput) (WafAntiCcRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_anticc
		SET url = ?, method = ?, threshold = ?, ` + "`window`" + ` = ?, action = ?, behavior = ?, status = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.URL,
		input.Method,
		nullableInt(input.Threshold),
		nullableInt(input.Window),
		nullableServerString(input.Action),
		input.Behavior,
		input.Status,
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafAntiCcRule{}, errNotFound
		}
		return WafAntiCcRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafAntiCcRule{}, err
	}
	if affected == 0 {
		return WafAntiCcRule{}, errNotFound
	}

	return WafAntiCcRule{
		ID:        ruleID,
		WafRuleID:  wafRuleID,
		URL:       input.URL,
		Method:    input.Method,
		Threshold: input.Threshold,
		Window:    input.Window,
		Action:    input.Action,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafAntiCcStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_anticc WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafAntiCcStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_anticc WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}

func nullIntValue(value sql.NullInt64) int {
	if value.Valid {
		return int(value.Int64)
	}
	return 0
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}
