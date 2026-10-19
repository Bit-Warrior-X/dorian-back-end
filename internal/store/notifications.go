package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

var errNotificationBadRequest = errors.New("bad request")

// PanelNotification is one topbar alarm row for a panel user.
type PanelNotification struct {
	ID         int64  `json:"id"`
	EventKey   string `json:"eventKey"`
	Kind       string `json:"kind"`
	Severity   string `json:"severity"`
	Title      string `json:"title"`
	Body       string `json:"body"`
	Status     string `json:"status"`
	ReqID      string `json:"reqId,omitempty"`
	ServerID   *int64 `json:"serverId,omitempty"`
	ServerName string `json:"serverName,omitempty"`
	Read       bool   `json:"read"`
	Dismissed  bool   `json:"dismissed"`
	At         string `json:"at"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
}

// NotificationInput is used to upsert an alarm for a user.
type NotificationInput struct {
	EventKey   string
	Kind       string
	Severity   string
	Title      string
	Body       string
	Status     string
	ReqID      string
	ServerID   *int64
	ServerName string
	Read       bool
	At         time.Time
}

type NotificationStore interface {
	EnsureSchema(ctx context.Context) error
	ListActive(ctx context.Context, userID int64, limit int) ([]PanelNotification, error)
	Upsert(ctx context.Context, userID int64, input NotificationInput) (PanelNotification, error)
	MarkRead(ctx context.Context, userID int64, eventKey string) error
	MarkAllRead(ctx context.Context, userID int64) error
	Dismiss(ctx context.Context, userID int64, eventKey string) error
	DismissAll(ctx context.Context, userID int64) error
}

type notificationStore struct {
	db *sql.DB
}

func NewNotificationStore(db *sql.DB) NotificationStore {
	return &notificationStore{db: db}
}

func (store *notificationStore) EnsureSchema(ctx context.Context) error {
	_, err := store.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS panel_notifications (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) NOT NULL,
			event_key VARCHAR(191) NOT NULL,
			kind VARCHAR(32) NOT NULL DEFAULT 'info',
			severity VARCHAR(32) NOT NULL DEFAULT 'warning',
			title VARCHAR(255) NOT NULL DEFAULT '',
			body TEXT NOT NULL,
			status VARCHAR(32) NOT NULL DEFAULT '',
			req_id VARCHAR(64) NOT NULL DEFAULT '',
			server_id BIGINT(20) DEFAULT NULL,
			server_name VARCHAR(255) NOT NULL DEFAULT '',
			is_read TINYINT(1) NOT NULL DEFAULT 0,
			is_dismissed TINYINT(1) NOT NULL DEFAULT 0,
			event_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY uq_panel_notifications_user_event (user_id, event_key),
			KEY idx_panel_notifications_user_active (user_id, is_dismissed, event_at),
			CONSTRAINT fk_panel_notifications_user
				FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

func (store *notificationStore) ListActive(ctx context.Context, userID int64, limit int) ([]PanelNotification, error) {
	if limit <= 0 || limit > 100 {
		limit = 40
	}
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, event_key, kind, severity, title, body, status, req_id, server_id, server_name,
		       is_read, is_dismissed, event_at, created_at, updated_at
		FROM panel_notifications
		WHERE user_id = ? AND is_dismissed = 0
		ORDER BY
			(status = 'ongoing') DESC,
			event_at DESC,
			id DESC
		LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PanelNotification
	for rows.Next() {
		item, err := scanPanelNotification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (store *notificationStore) Upsert(ctx context.Context, userID int64, input NotificationInput) (PanelNotification, error) {
	eventKey := strings.TrimSpace(input.EventKey)
	if userID <= 0 || eventKey == "" {
		return PanelNotification{}, errNotificationBadRequest
	}
	at := input.At
	if at.IsZero() {
		at = time.Now().UTC()
	}
	kind := strings.TrimSpace(input.Kind)
	if kind == "" {
		kind = "info"
	}
	severity := strings.TrimSpace(input.Severity)
	if severity == "" {
		severity = "warning"
	}
	title := strings.TrimSpace(input.Title)
	if title == "" {
		title = "Alarm"
	}
	readVal := 0
	if input.Read {
		readVal = 1
	}

	_, err := store.db.ExecContext(ctx, `
		INSERT INTO panel_notifications (
			user_id, event_key, kind, severity, title, body, status, req_id,
			server_id, server_name, is_read, is_dismissed, event_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
		ON DUPLICATE KEY UPDATE
			kind = VALUES(kind),
			severity = VALUES(severity),
			title = VALUES(title),
			body = VALUES(body),
			status = VALUES(status),
			req_id = VALUES(req_id),
			server_id = VALUES(server_id),
			server_name = VALUES(server_name),
			event_at = IF(
				is_dismissed = 1,
				event_at,
				IF(VALUES(status) <> status OR VALUES(title) <> title, VALUES(event_at), event_at)
			),
			is_read = IF(
				is_dismissed = 1,
				is_read,
				IF(VALUES(status) <> status OR VALUES(title) <> title, 0, is_read)
			),
			updated_at = CURRENT_TIMESTAMP`,
		userID,
		eventKey,
		kind,
		severity,
		title,
		strings.TrimSpace(input.Body),
		strings.TrimSpace(input.Status),
		strings.TrimSpace(input.ReqID),
		nullServerID(input.ServerID),
		strings.TrimSpace(input.ServerName),
		readVal,
		at.UTC(),
	)
	if err != nil {
		return PanelNotification{}, err
	}

	return store.getByEventKey(ctx, userID, eventKey)
}

func (store *notificationStore) MarkRead(ctx context.Context, userID int64, eventKey string) error {
	eventKey = strings.TrimSpace(eventKey)
	if userID <= 0 || eventKey == "" {
		return errNotificationBadRequest
	}
	_, err := store.db.ExecContext(ctx, `
		UPDATE panel_notifications
		SET is_read = 1, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND event_key = ? AND is_dismissed = 0`,
		userID, eventKey)
	return err
}

func (store *notificationStore) MarkAllRead(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return errNotificationBadRequest
	}
	_, err := store.db.ExecContext(ctx, `
		UPDATE panel_notifications
		SET is_read = 1, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND is_dismissed = 0 AND is_read = 0`,
		userID)
	return err
}

func (store *notificationStore) Dismiss(ctx context.Context, userID int64, eventKey string) error {
	eventKey = strings.TrimSpace(eventKey)
	if userID <= 0 || eventKey == "" {
		return errNotificationBadRequest
	}
	res, err := store.db.ExecContext(ctx, `
		UPDATE panel_notifications
		SET is_dismissed = 1, is_read = 1, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND event_key = ? AND is_dismissed = 0`,
		userID, eventKey)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Already dismissed or unknown — treat as success so the UI can clear it.
		return nil
	}
	return nil
}

func (store *notificationStore) DismissAll(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return errNotificationBadRequest
	}
	_, err := store.db.ExecContext(ctx, `
		UPDATE panel_notifications
		SET is_dismissed = 1, is_read = 1, updated_at = CURRENT_TIMESTAMP
		WHERE user_id = ? AND is_dismissed = 0`,
		userID)
	return err
}

func (store *notificationStore) getByEventKey(ctx context.Context, userID int64, eventKey string) (PanelNotification, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT id, event_key, kind, severity, title, body, status, req_id, server_id, server_name,
		       is_read, is_dismissed, event_at, created_at, updated_at
		FROM panel_notifications
		WHERE user_id = ? AND event_key = ?
		LIMIT 1`, userID, eventKey)
	return scanPanelNotification(row)
}

type notificationScanner interface {
	Scan(dest ...any) error
}

func scanPanelNotification(row notificationScanner) (PanelNotification, error) {
	var item PanelNotification
	var serverID sql.NullInt64
	var eventAt, createdAt, updatedAt time.Time
	var isRead, isDismissed int
	if err := row.Scan(
		&item.ID,
		&item.EventKey,
		&item.Kind,
		&item.Severity,
		&item.Title,
		&item.Body,
		&item.Status,
		&item.ReqID,
		&serverID,
		&item.ServerName,
		&isRead,
		&isDismissed,
		&eventAt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return PanelNotification{}, err
	}
	if serverID.Valid {
		id := serverID.Int64
		item.ServerID = &id
	}
	item.Read = isRead != 0
	item.Dismissed = isDismissed != 0
	item.At = eventAt.UTC().Format(time.RFC3339)
	item.CreatedAt = createdAt.UTC().Format(time.RFC3339)
	item.UpdatedAt = updatedAt.UTC().Format(time.RFC3339)
	return item, nil
}

func nullServerID(v *int64) sql.NullInt64 {
	if v == nil || *v <= 0 {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Int64: *v, Valid: true}
}
