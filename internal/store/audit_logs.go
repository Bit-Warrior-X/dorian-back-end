package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type AuditLog struct {
	ID           int64  `json:"id"`
	Action       string `json:"action"`
	Category     string `json:"category"`
	ResourceType string `json:"resourceType"`
	ResourceID   *int64 `json:"resourceId"`
	ResourceName string `json:"resourceName"`
	ActorUserID  *int64 `json:"actorUserId"`
	ActorName    string `json:"actorName"`
	ActorEmail   string `json:"actorEmail"`
	ActorRole    string `json:"actorRole"`
	IPAddress    string `json:"ipAddress"`
	UserAgent    string `json:"userAgent"`
	HTTPMethod   string `json:"httpMethod"`
	Path         string `json:"path"`
	StatusCode   int    `json:"statusCode"`
	Details      string `json:"details"`
	CreatedAt    string `json:"createdAt"`
}

type AuditLogInput struct {
	Action       string
	Category     string
	ResourceType string
	ResourceID   *int64
	ResourceName string
	ActorUserID  *int64
	ActorName    string
	ActorEmail   string
	ActorRole    string
	IPAddress    string
	UserAgent    string
	HTTPMethod   string
	Path         string
	StatusCode   int
	Details      string
}

type AuditLogFilter struct {
	Limit       int
	Category    string
	Action      string
	ActorUserID int64
	Search      string
}

type AuditLogStore interface {
	Create(ctx context.Context, input AuditLogInput) error
	List(ctx context.Context, filter AuditLogFilter) ([]AuditLog, error)
}

type auditLogStore struct {
	db *sql.DB
}

func NewAuditLogStore(db *sql.DB) AuditLogStore {
	return &auditLogStore{db: db}
}

func (store *auditLogStore) Create(ctx context.Context, input AuditLogInput) error {
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			action, category, resource_type, resource_id, resource_name,
			actor_user_id, actor_name, actor_email, actor_role,
			ip_address, user_agent, http_method, path, status_code, details, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
		strings.TrimSpace(input.Action),
		strings.TrimSpace(input.Category),
		nullableString(input.ResourceType),
		nullableInt64Ptr(input.ResourceID),
		nullableString(input.ResourceName),
		nullableInt64Ptr(input.ActorUserID),
		nullableString(input.ActorName),
		nullableString(input.ActorEmail),
		nullableString(input.ActorRole),
		nullableString(input.IPAddress),
		nullableString(trimAuditUserAgent(input.UserAgent)),
		nullableString(input.HTTPMethod),
		nullableString(input.Path),
		nullableInt(input.StatusCode),
		nullableString(input.Details),
	)
	return err
}

func (store *auditLogStore) List(ctx context.Context, filter AuditLogFilter) ([]AuditLog, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	query := `
		SELECT id, action, category, resource_type, resource_id, resource_name,
			actor_user_id, actor_name, actor_email, actor_role,
			ip_address, user_agent, http_method, path, status_code, details, created_at
		FROM audit_logs
		WHERE 1=1`
	args := make([]any, 0, 8)

	if category := strings.TrimSpace(filter.Category); category != "" {
		query += " AND category = ?"
		args = append(args, category)
	}
	if action := strings.TrimSpace(filter.Action); action != "" {
		query += " AND action = ?"
		args = append(args, action)
	}
	if filter.ActorUserID > 0 {
		query += " AND actor_user_id = ?"
		args = append(args, filter.ActorUserID)
	}
	if search := strings.TrimSpace(filter.Search); search != "" {
		like := "%" + search + "%"
		query += " AND (actor_name LIKE ? OR actor_email LIKE ? OR resource_name LIKE ? OR details LIKE ? OR path LIKE ? OR ip_address LIKE ?)"
		args = append(args, like, like, like, like, like, like)
	}

	query += " ORDER BY created_at DESC LIMIT ?"
	args = append(args, limit)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := make([]AuditLog, 0, limit)
	for rows.Next() {
		var item AuditLog
		var resourceType sql.NullString
		var resourceName sql.NullString
		var actorName sql.NullString
		var actorEmail sql.NullString
		var actorRole sql.NullString
		var ipAddress sql.NullString
		var userAgent sql.NullString
		var httpMethod sql.NullString
		var path sql.NullString
		var details sql.NullString
		var resourceID sql.NullInt64
		var actorUserID sql.NullInt64
		var statusCode sql.NullInt64
		var createdAt sql.NullTime

		if err := rows.Scan(
			&item.ID,
			&item.Action,
			&item.Category,
			&resourceType,
			&resourceID,
			&resourceName,
			&actorUserID,
			&actorName,
			&actorEmail,
			&actorRole,
			&ipAddress,
			&userAgent,
			&httpMethod,
			&path,
			&statusCode,
			&details,
			&createdAt,
		); err != nil {
			return nil, err
		}

		item.ResourceType = resourceType.String
		item.ResourceName = resourceName.String
		item.ActorName = actorName.String
		item.ActorEmail = actorEmail.String
		item.ActorRole = actorRole.String
		item.IPAddress = ipAddress.String
		item.UserAgent = userAgent.String
		item.HTTPMethod = httpMethod.String
		item.Path = path.String
		item.Details = details.String
		item.CreatedAt = formatTimestamp(createdAt)
		if resourceID.Valid {
			value := resourceID.Int64
			item.ResourceID = &value
		}
		if actorUserID.Valid {
			value := actorUserID.Int64
			item.ActorUserID = &value
		}
		if statusCode.Valid {
			item.StatusCode = int(statusCode.Int64)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func nullableInt64Ptr(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func trimAuditUserAgent(value string) string {
	value = strings.TrimSpace(value)
	if len(value) <= 512 {
		return value
	}
	return value[:512]
}

func FormatAuditResourceLabel(category string, resourceID int64, suffix string) string {
	label := strings.TrimSpace(category)
	if resourceID > 0 {
		label = fmt.Sprintf("%s #%d", label, resourceID)
	}
	if suffix = strings.TrimSpace(suffix); suffix != "" {
		if label != "" {
			return label + " · " + suffix
		}
		return suffix
	}
	return label
}
