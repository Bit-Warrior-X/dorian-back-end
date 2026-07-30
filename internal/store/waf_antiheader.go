package store

import (
	"context"
	"database/sql"
	"strings"
)

type WafAntiHeaderRule struct {
	ID        int64  `json:"id"`
	WafRuleID  int64  `json:"wafRuleId"`
	URL       string `json:"url"`
	Header    string `json:"header"`
	Value     string `json:"value"`
	BlockMode string `json:"blockMode"`
	Behavior  string `json:"behavior"`
	Status    string `json:"status"`
}

type WafAntiHeaderInput struct {
	URL       string
	Header    string
	Value     string
	BlockMode string
	Behavior  string
	Status    string
}

type WafAntiHeaderStore interface {
	ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafAntiHeaderRule, error)
	Create(ctx context.Context, wafRuleID int64, input WafAntiHeaderInput) (WafAntiHeaderRule, error)
	Update(ctx context.Context, wafRuleID, ruleID int64, input WafAntiHeaderInput) (WafAntiHeaderRule, error)
	Delete(ctx context.Context, wafRuleID, ruleID int64) error
	DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error
}

type wafAntiHeaderStore struct {
	db *sql.DB
}

func NewWafAntiHeaderStore(db *sql.DB) WafAntiHeaderStore {
	return &wafAntiHeaderStore{db: db}
}

func (store *wafAntiHeaderStore) ListByWafRule(ctx context.Context, wafRuleID int64) ([]WafAntiHeaderRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, waf_rule_id, url, header, value, block_mode, behavior, status
		FROM waf_antiheader
		WHERE waf_rule_id = ?
		ORDER BY id DESC`, wafRuleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []WafAntiHeaderRule
	for rows.Next() {
		var rule WafAntiHeaderRule
		var blockMode sql.NullString
		var status sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.WafRuleID,
			&rule.URL,
			&rule.Header,
			&rule.Value,
			&blockMode,
			&rule.Behavior,
			&status,
		); err != nil {
			return nil, err
		}
		rule.BlockMode = nullStringValue(blockMode)
		rule.Status = nullStringValue(status)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *wafAntiHeaderStore) Create(ctx context.Context, wafRuleID int64, input WafAntiHeaderInput) (WafAntiHeaderRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO waf_antiheader (waf_rule_id, url, header, value, block_mode, behavior, status)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		wafRuleID,
		input.URL,
		input.Header,
		input.Value,
		nullableServerString(input.BlockMode),
		input.Behavior,
		nullableServerString(input.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafAntiHeaderRule{}, errNotFound
		}
		return WafAntiHeaderRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return WafAntiHeaderRule{}, err
	}

	return WafAntiHeaderRule{
		ID:        id,
		WafRuleID:  wafRuleID,
		URL:       input.URL,
		Header:    input.Header,
		Value:     input.Value,
		BlockMode: input.BlockMode,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafAntiHeaderStore) Update(ctx context.Context, wafRuleID, ruleID int64, input WafAntiHeaderInput) (WafAntiHeaderRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE waf_antiheader
		SET url = ?, header = ?, value = ?, block_mode = ?, behavior = ?, status = ?
		WHERE id = ? AND waf_rule_id = ?`,
		input.URL,
		input.Header,
		input.Value,
		nullableServerString(input.BlockMode),
		input.Behavior,
		nullableServerString(input.Status),
		ruleID,
		wafRuleID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return WafAntiHeaderRule{}, errNotFound
		}
		return WafAntiHeaderRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return WafAntiHeaderRule{}, err
	}
	if affected == 0 {
		return WafAntiHeaderRule{}, errNotFound
	}

	return WafAntiHeaderRule{
		ID:        ruleID,
		WafRuleID:  wafRuleID,
		URL:       input.URL,
		Header:    input.Header,
		Value:     input.Value,
		BlockMode: input.BlockMode,
		Behavior:  input.Behavior,
		Status:    input.Status,
	}, nil
}

func (store *wafAntiHeaderStore) Delete(ctx context.Context, wafRuleID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM waf_antiheader WHERE id = ? AND waf_rule_id = ?`,
		ruleID,
		wafRuleID,
	)
	return err
}

func (store *wafAntiHeaderStore) DeleteBatch(ctx context.Context, wafRuleID int64, ruleIDs []int64) error {
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

	query := "DELETE FROM waf_antiheader WHERE id IN (" + strings.Join(placeholders, ",") + ") AND waf_rule_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
