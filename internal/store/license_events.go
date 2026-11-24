package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// License event types recorded for the Licensing history panel.
const (
	LicenseEventActivated       = "activated"
	LicenseEventCancelled       = "cancelled"
	LicenseEventCancelScheduled = "cancel_scheduled"
	LicenseEventResumed         = "resumed"
	LicenseEventRenewed         = "renewed"
	LicenseEventReactivated     = "reactivated"
)

// LicenseEvent is one row in the license history timeline.
type LicenseEvent struct {
	ID        int64     `json:"id"`
	LicenseID int64     `json:"licenseId"`
	UserID    int64     `json:"userId"`
	Scope     string    `json:"scope"`
	TargetID  int64     `json:"targetId"`
	EventType string    `json:"eventType"`
	OrderID   *int64    `json:"orderId,omitempty"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	EventAt   time.Time `json:"eventAt"`
}

// LicenseHistoryOrder is a compact related order for the history panel.
type LicenseHistoryOrder struct {
	ID                int64      `json:"id"`
	Kind              string     `json:"kind"`
	Purpose           string     `json:"purpose"`
	Status            string     `json:"status"`
	Period            string     `json:"period"`
	Currency          string     `json:"currency"`
	Total             float64    `json:"total"`
	InvoiceNo         string     `json:"invoiceNo,omitempty"`
	Summary           string     `json:"summary"`
	PlatformServerIDs []int64    `json:"platformServerIds,omitempty"`
	EdgeNames         []string   `json:"edgeNames,omitempty"`
	SiteDomains       []string   `json:"siteDomains,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	SubmittedAt       *time.Time `json:"submittedAt,omitempty"`
	PaidAt            *time.Time `json:"paidAt,omitempty"`
	ActivatedAt       *time.Time `json:"activatedAt,omitempty"`
	CancelledAt       *time.Time `json:"cancelledAt,omitempty"`
}

// LicenseHistorySummary rolls up commercial activity for the history panel.
type LicenseHistorySummary struct {
	OrderCount      int     `json:"orderCount"`
	CompletedOrders int     `json:"completedOrders"`
	CancelledOrders int     `json:"cancelledOrders"`
	RenewalOrders   int     `json:"renewalOrders"`
	CancelEvents    int     `json:"cancelEvents"`
	Reactivations   int     `json:"reactivations"`
	TotalSpent      float64 `json:"totalSpent"`
	Currency        string  `json:"currency"`
	FirstLicensedAt string  `json:"firstLicensedAt,omitempty"`
	LastEventAt     string  `json:"lastEventAt,omitempty"`
	LastEventType   string  `json:"lastEventType,omitempty"`
}

func (s *orderStore) ensureLicenseEventsSchema(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS license_events (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			license_id BIGINT(20) NOT NULL,
			user_id BIGINT(20) NOT NULL DEFAULT 0,
			scope VARCHAR(8) NOT NULL,
			target_id BIGINT(20) NOT NULL,
			event_type VARCHAR(32) NOT NULL,
			order_id BIGINT(20) DEFAULT NULL,
			title VARCHAR(255) NOT NULL DEFAULT '',
			body TEXT NOT NULL,
			event_at DATETIME NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_license_events_license (license_id, event_at),
			KEY idx_license_events_target (scope, target_id, event_at)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`)
	return err
}

func (s *orderStore) AppendLicenseEvent(ctx context.Context, event LicenseEvent) error {
	if event.LicenseID <= 0 || event.Scope == "" || event.TargetID <= 0 || event.EventType == "" {
		return nil
	}
	if event.EventAt.IsZero() {
		event.EventAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO license_events (license_id, user_id, scope, target_id, event_type, order_id, title, body, event_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.LicenseID, event.UserID, event.Scope, event.TargetID, event.EventType, event.OrderID,
		strings.TrimSpace(event.Title), strings.TrimSpace(event.Body), event.EventAt.UTC())
	return err
}

func (s *orderStore) ListLicenseEvents(ctx context.Context, licenseID int64) ([]LicenseEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, license_id, user_id, scope, target_id, event_type, order_id, title, body, event_at
		FROM license_events
		WHERE license_id = ?
		ORDER BY event_at DESC, id DESC
		LIMIT 100`, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LicenseEvent, 0)
	for rows.Next() {
		var event LicenseEvent
		var orderID sql.NullInt64
		if err := rows.Scan(&event.ID, &event.LicenseID, &event.UserID, &event.Scope, &event.TargetID,
			&event.EventType, &orderID, &event.Title, &event.Body, &event.EventAt); err != nil {
			return nil, err
		}
		if orderID.Valid {
			event.OrderID = &orderID.Int64
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

func (s *orderStore) ListLicenseEventsForTarget(ctx context.Context, scope string, targetID int64) ([]LicenseEvent, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, license_id, user_id, scope, target_id, event_type, order_id, title, body, event_at
		FROM license_events
		WHERE scope = ? AND target_id = ?
		ORDER BY event_at DESC, id DESC
		LIMIT 100`, scope, targetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]LicenseEvent, 0)
	for rows.Next() {
		var event LicenseEvent
		var orderID sql.NullInt64
		if err := rows.Scan(&event.ID, &event.LicenseID, &event.UserID, &event.Scope, &event.TargetID,
			&event.EventType, &orderID, &event.Title, &event.Body, &event.EventAt); err != nil {
			return nil, err
		}
		if orderID.Valid {
			event.OrderID = &orderID.Int64
		}
		out = append(out, event)
	}
	return out, rows.Err()
}

// ListOrdersForTarget returns orders that placed or renewed this site/edge.
func (s *orderStore) ListOrdersForTarget(ctx context.Context, userID int64, scope string, targetID int64) ([]Order, error) {
	orders, err := s.List(ctx, userID, nil)
	if err != nil {
		return nil, err
	}
	out := make([]Order, 0)
	for _, order := range orders {
		if orderTouchesTarget(order, scope, targetID) {
			out = append(out, order)
		}
	}
	return out, nil
}

func orderTouchesTarget(order Order, scope string, targetID int64) bool {
	if targetID <= 0 {
		return false
	}
	if scope == LicenseScopeSite {
		for _, site := range order.Details.Sites {
			if site.SiteID == targetID {
				return true
			}
		}
		return false
	}
	if scope == LicenseScopeServer {
		for _, edge := range order.Details.Edges {
			if edge.ServerID == targetID {
				return true
			}
		}
		for _, id := range order.Details.UpgradeServerIDs {
			if id == targetID {
				return true
			}
		}
		for _, id := range order.Details.PlatformServerIDs {
			if id == targetID {
				return true
			}
		}
		return false
	}
	return false
}
