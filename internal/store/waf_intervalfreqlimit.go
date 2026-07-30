package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafIntervalRule struct {
	ID           int64  `json:"id"`
	WafRuleID     int64  `json:"wafRuleId"`
	URL          string `json:"url"`
	TimeSeconds  int    `json:"time"`
	RequestCount int    `json:"requestCount"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type WafIntervalInput struct {
	URL          string
	TimeSeconds  int
	RequestCount int
	Behavior     string
	Status       string
}

type WafIntervalStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafIntervalRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafIntervalInput) (WafIntervalRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafIntervalInput) (WafIntervalRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafIntervalStore struct {
	db *sql.DB
}

func NewWafIntervalStore(db *sql.DB) WafIntervalStore {
	return &wafIntervalStore{db: db}
}

func (store *wafIntervalStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafIntervalRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, url, time, request_count, behavior, status
		FROM waf_intervalfreqlimit
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafIntervalRule
	for rows.Next() {
		var rule WafIntervalRule
		var status sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.URL,
			&rule.TimeSeconds,
			&rule.RequestCount,
			&rule.Behavior,
			&status,
		); err != nil {
			return nil, err
		}
		rule.Status = nullStringValue(status)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafIntervalStore) Create(ctx context.Context, wafRuleID int64, input WafIntervalInput) (WafIntervalRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_intervalfreqlimit (waf_rule_id, url, time, request_count, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.URL,
		input.TimeSeconds,
		input.RequestCount,
		input.Behavior,
		nullableServerString(input.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafIntervalRule{}, errNotFound
		}
		return WafIntervalRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafIntervalRule{}, err
	}

	return WafIntervalRule{
		ID:           id,
		WafRuleID:     wafRuleID,
		URL:          input.URL,
		TimeSeconds:  input.TimeSeconds,
		RequestCount: input.RequestCount,
		Behavior:     input.Behavior,
		Status:       input.Status,
	}, nil
}

func (store *wafIntervalStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafIntervalInput) (WafIntervalRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_intervalfreqlimit
		SET url = ?, time = ?, request_count = ?, behavior = ?, status = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.URL,
		input.TimeSeconds,
		input.RequestCount,
		input.Behavior,
		nullableServerString(input.Status),
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafIntervalRule{}, errNotFound
		}
		return WafIntervalRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafIntervalRule{}, err
	}
	if affected == 0 {
		return WafIntervalRule{}, errNotFound
	}

	return WafIntervalRule{
		ID:           ruleID,
		WafRuleID:     wafRuleID,
		URL:          input.URL,
		TimeSeconds:  input.TimeSeconds,
		RequestCount: input.RequestCount,
		Behavior:     input.Behavior,
		Status:       input.Status,
	}, nil
}

func (store *wafIntervalStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_intervalfreqlimit WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafIntervalStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_intervalfreqlimit WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
