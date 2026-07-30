package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafSecondRule struct {
	ID           int64  `json:"id"`
	WafRuleID     int64  `json:"wafRuleId"`
	URL          string `json:"url"`
	RequestCount int    `json:"requestCount"`
	Burst        int    `json:"burst"`
	Behavior     string `json:"behavior"`
	Status       string `json:"status"`
}

type WafSecondInput struct {
	URL          string
	RequestCount int
	Burst        int
	Behavior     string
	Status       string
}

type WafSecondStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafSecondRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafSecondInput) (WafSecondRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafSecondInput) (WafSecondRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafSecondStore struct {
	db *sql.DB
}

func NewWafSecondStore(db *sql.DB) WafSecondStore {
	return &wafSecondStore{db: db}
}

func (store *wafSecondStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafSecondRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, url, request_count, burst, behavior, status
		FROM waf_secondfreqlimit
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafSecondRule
	for rows.Next() {
		var rule WafSecondRule
		var status sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.URL,
			&rule.RequestCount,
			&rule.Burst,
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

func (store *wafSecondStore) Create(ctx context.Context, wafRuleID int64, input WafSecondInput) (WafSecondRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_secondfreqlimit (waf_rule_id, url, request_count, burst, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.URL,
		input.RequestCount,
		input.Burst,
		input.Behavior,
		nullableServerString(input.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafSecondRule{}, errNotFound
		}
		return WafSecondRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafSecondRule{}, err
	}

	return WafSecondRule{
		ID:           id,
		WafRuleID:     wafRuleID,
		URL:          input.URL,
		RequestCount: input.RequestCount,
		Burst:        input.Burst,
		Behavior:     input.Behavior,
		Status:       input.Status,
	}, nil
}

func (store *wafSecondStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafSecondInput) (WafSecondRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_secondfreqlimit
		SET url = ?, request_count = ?, burst = ?, behavior = ?, status = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.URL,
		input.RequestCount,
		input.Burst,
		input.Behavior,
		nullableServerString(input.Status),
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafSecondRule{}, errNotFound
		}
		return WafSecondRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafSecondRule{}, err
	}
	if affected == 0 {
		return WafSecondRule{}, errNotFound
	}

	return WafSecondRule{
		ID:           ruleID,
		WafRuleID:     wafRuleID,
		URL:          input.URL,
		RequestCount: input.RequestCount,
		Burst:        input.Burst,
		Behavior:     input.Behavior,
		Status:       input.Status,
	}, nil
}

func (store *wafSecondStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_secondfreqlimit WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafSecondStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_secondfreqlimit WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
