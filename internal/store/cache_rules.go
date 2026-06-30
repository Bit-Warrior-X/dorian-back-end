package store

import (
	"context"
	"database/sql"
	"strings"
)

type CacheRule struct {
	ID               int64  `json:"id"`
	ServerID         int64  `json:"serverId"`
	RuleName         string `json:"ruleName"`
	RuleType         string `json:"ruleType"`
	CachingTime      int    `json:"cachingTime"`
	URL              string `json:"url"`
	FileTypes        string `json:"fileTypes"`
	Priority         int    `json:"priority"`
	CacheSlice       float64 `json:"cacheSlice"`
	WithoutParameter string `json:"withoutParameter"`
	CacheMode        string `json:"cacheMode"`
	Status           string `json:"status"`
}

type CacheRuleInput struct {
	RuleName         string
	RuleType         string
	CachingTime      int
	URL              string
	FileTypes        string
	Priority         int
	CacheSlice       float64
	WithoutParameter string
	CacheMode        string
	Status           string
}

type CacheRuleStore interface {
	ListByServer(ctx context.Context, serverID int64) ([]CacheRule, error)
	Create(ctx context.Context, serverID int64, rule CacheRuleInput) (CacheRule, error)
	Update(ctx context.Context, serverID, ruleID int64, rule CacheRuleInput) (CacheRule, error)
	Delete(ctx context.Context, serverID, ruleID int64) error
	DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error
}

type cacheRuleStore struct {
	db *sql.DB
}

func NewCacheRuleStore(db *sql.DB) CacheRuleStore {
	return &cacheRuleStore{db: db}
}

func NormalizeCacheRuleName(name string) string {
	return strings.TrimSpace(name)
}

func CacheRuleNameExists(list []CacheRule, ruleName string, excludeID int64) bool {
	normalized := strings.ToLower(NormalizeCacheRuleName(ruleName))
	if normalized == "" {
		return false
	}
	for _, rule := range list {
		if excludeID != 0 && rule.ID == excludeID {
			continue
		}
		if strings.ToLower(NormalizeCacheRuleName(rule.RuleName)) == normalized {
			return true
		}
	}
	return false
}

func (store *cacheRuleStore) ListByServer(ctx context.Context, serverID int64) ([]CacheRule, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, server_id, rule_name, rule_type, caching_time, url, file_types,
		       priority, cache_slice, without_parameter, cache_mode, status
		FROM cache_rules
		WHERE server_id = ?
		ORDER BY priority DESC, id ASC`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []CacheRule
	for rows.Next() {
		var rule CacheRule
		var ruleType sql.NullString
		var status sql.NullString
		var withoutParameter sql.NullString
		var cacheMode sql.NullString
		if err := rows.Scan(
			&rule.ID,
			&rule.ServerID,
			&rule.RuleName,
			&ruleType,
			&rule.CachingTime,
			&rule.URL,
			&rule.FileTypes,
			&rule.Priority,
			&rule.CacheSlice,
			&withoutParameter,
			&cacheMode,
			&status,
		); err != nil {
			return nil, err
		}
		rule.RuleType = nullStringValue(ruleType)
		rule.WithoutParameter = nullStringValue(withoutParameter)
		rule.CacheMode = nullStringValue(cacheMode)
		rule.Status = nullStringValue(status)
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rules, nil
}

func (store *cacheRuleStore) Create(ctx context.Context, serverID int64, rule CacheRuleInput) (CacheRule, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO cache_rules (
			server_id, rule_name, rule_type, caching_time, url, file_types,
			priority, cache_slice, without_parameter, cache_mode, status
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		serverID,
		rule.RuleName,
		nullableServerString(rule.RuleType),
		rule.CachingTime,
		rule.URL,
		rule.FileTypes,
		rule.Priority,
		rule.CacheSlice,
		nullableServerString(rule.WithoutParameter),
		nullableServerString(rule.CacheMode),
		nullableServerString(rule.Status),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return CacheRule{}, errNotFound
		}
		return CacheRule{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return CacheRule{}, err
	}

	return CacheRule{
		ID:               id,
		ServerID:         serverID,
		RuleName:         rule.RuleName,
		RuleType:         rule.RuleType,
		CachingTime:      rule.CachingTime,
		URL:              rule.URL,
		FileTypes:        rule.FileTypes,
		Priority:         rule.Priority,
		CacheSlice:       rule.CacheSlice,
		WithoutParameter: rule.WithoutParameter,
		CacheMode:        rule.CacheMode,
		Status:           rule.Status,
	}, nil
}

func (store *cacheRuleStore) Update(ctx context.Context, serverID, ruleID int64, rule CacheRuleInput) (CacheRule, error) {
	result, err := store.db.ExecContext(ctx, `
		UPDATE cache_rules
		SET rule_name = ?, rule_type = ?, caching_time = ?, url = ?, file_types = ?,
		    priority = ?, cache_slice = ?, without_parameter = ?, cache_mode = ?, status = ?
		WHERE id = ? AND server_id = ?`,
		rule.RuleName,
		nullableServerString(rule.RuleType),
		rule.CachingTime,
		rule.URL,
		rule.FileTypes,
		rule.Priority,
		rule.CacheSlice,
		nullableServerString(rule.WithoutParameter),
		nullableServerString(rule.CacheMode),
		nullableServerString(rule.Status),
		ruleID,
		serverID,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return CacheRule{}, errNotFound
		}
		return CacheRule{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return CacheRule{}, err
	}
	if affected == 0 {
		return CacheRule{}, errNotFound
	}

	return CacheRule{
		ID:               ruleID,
		ServerID:         serverID,
		RuleName:         rule.RuleName,
		RuleType:         rule.RuleType,
		CachingTime:      rule.CachingTime,
		URL:              rule.URL,
		FileTypes:        rule.FileTypes,
		Priority:         rule.Priority,
		CacheSlice:       rule.CacheSlice,
		WithoutParameter: rule.WithoutParameter,
		CacheMode:        rule.CacheMode,
		Status:           rule.Status,
	}, nil
}

func (store *cacheRuleStore) Delete(ctx context.Context, serverID, ruleID int64) error {
	_, err := store.db.ExecContext(ctx, `
		DELETE FROM cache_rules WHERE id = ? AND server_id = ?`,
		ruleID,
		serverID,
	)
	return err
}

func (store *cacheRuleStore) DeleteBatch(ctx context.Context, serverID int64, ruleIDs []int64) error {
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
	args = append(args, serverID)

	query := "DELETE FROM cache_rules WHERE id IN (" + strings.Join(placeholders, ",") + ") AND server_id = ?"
	_, err := store.db.ExecContext(ctx, query, args...)
	return err
}
