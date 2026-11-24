package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"vue-project-backend/internal/secretbox"
)

const (
	OrderStatusDraft           = "draft"
	OrderStatusAwaitingPayment = "awaiting_payment"
	OrderStatusAwaitingSetup   = "awaiting_setup"
	OrderStatusProvisioning    = "provisioning"
	OrderStatusActive          = "active"
	OrderStatusCancelled       = "cancelled"

	OrderKindNew     = "new"
	OrderKindAddon   = "addon"
	OrderKindRenewal = "renewal"

	OrderPurposeSiteOwn      = "site_own"
	OrderPurposeSitePlatform = "site_platform"
	OrderPurposeEdge         = "edge"
	OrderPurposeEdgeSite     = "edge_site"
	OrderPurposeAddon        = "addon"
	OrderPurposeRenewal      = "renewal"

	LicenseScopeServer = "server"
	LicenseScopeSite   = "site"

	LicenseKindL4           = "L4"
	LicenseKindL7           = "L7"
	LicenseKindUnified      = "Unified"
	LicenseKindSiteOwn      = "SITE_OWN"
	LicenseKindSitePlatform = "SITE_PLATFORM"

	LicenseStatusActive    = "active"
	LicenseStatusPastDue   = "past_due"
	LicenseStatusExpired   = "expired"
	LicenseStatusCancelled = "cancelled"

	CatalogEdgeL4       = "EDGE_L4"
	CatalogEdgeL7       = "EDGE_L7"
	CatalogL4Addon      = "L4_ADDON"
	CatalogSiteOwn      = "SITE_OWN"
	CatalogSitePlatform = "SITE_PLATFORM"
	CatalogSetupFee     = "SETUP_FEE"

	ServerKindPlatform = "platform"
	ServerKindCustomer = "customer"
)

// CatalogItem is an orderable price row in license_plans (category = 'catalog').
type CatalogItem struct {
	Code         string  `json:"code"`
	Title        string  `json:"title"`
	Tagline      string  `json:"tagline"`
	MonthlyPrice float64 `json:"monthlyPrice"`
	AnnualPrice  float64 `json:"annualPrice"`
	OneTime      bool    `json:"oneTime"`
	SortOrder    int     `json:"sortOrder"`
}

type OrderEdge struct {
	Name             string `json:"name"`
	IP               string `json:"ip"`
	SSHPort          string `json:"sshPort"`
	SSHUser          string `json:"sshUser"`
	SSHAuthType      string `json:"sshAuthType"`
	SSHPassword      string `json:"sshPassword,omitempty"`
	SSHPrivateKey    string `json:"sshPrivateKey,omitempty"`
	SSHKeyPassphrase string `json:"sshKeyPassphrase,omitempty"`
	HasSSHPassword   bool   `json:"hasSshPassword"`
	HasSSHKey        bool   `json:"hasSshKey"`
	L4               bool   `json:"l4"`
	L7               bool   `json:"l7"`
	VersionUUID      string `json:"versionUuid,omitempty"`
	ServerID         int64  `json:"serverId,omitempty"`
	Error            string `json:"error,omitempty"`
}

type OrderOrigin struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
}

type OrderSite struct {
	Domain  string        `json:"domain"`
	Origins []OrderOrigin `json:"origins"`
	// Origin and OriginProtocol mirror Origins[0] for drafts saved before multi-origin sites.
	Origin         string  `json:"origin"`
	OriginProtocol string  `json:"originProtocol"`
	Placement      string  `json:"placement"`
	ServerIDs      []int64 `json:"serverIds,omitempty"`
	SiteID         int64   `json:"siteId,omitempty"`
	Error          string  `json:"error,omitempty"`
}

type OrderDetails struct {
	Edges            []OrderEdge `json:"edges"`
	Sites            []OrderSite `json:"sites"`
	UpgradeServerIDs []int64     `json:"upgradeServerIds,omitempty"`
	UpgradesDone     []int64     `json:"upgradesDone,omitempty"`
	RenewLicenseIDs  []int64     `json:"renewLicenseIds,omitempty"`
	CoTermEnd        *time.Time  `json:"coTermEnd,omitempty"`
	// PlatformServerIDs are the Dorian edges chosen by the operator for platform sites.
	PlatformServerIDs []int64 `json:"platformServerIds,omitempty"`
}

type OrderItem struct {
	Code      string  `json:"code"`
	Label     string  `json:"label"`
	Quantity  int     `json:"quantity"`
	UnitPrice float64 `json:"unitPrice"`
	LineTotal float64 `json:"lineTotal"`
	Note      string  `json:"note,omitempty"`
}

type OrderPayment struct {
	ID             int64     `json:"id"`
	Amount         float64   `json:"amount"`
	Reference      string    `json:"reference"`
	PaidOn         time.Time `json:"paidOn"`
	RecordedBy     int64     `json:"recordedBy"`
	RecordedByName string    `json:"recordedByName,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
}

type Order struct {
	ID            int64          `json:"id"`
	UserID        int64          `json:"userId"`
	UserName      string         `json:"userName,omitempty"`
	UserEmail     string         `json:"userEmail,omitempty"`
	CreatedBy     int64          `json:"createdBy"`
	ParentOrderID *int64         `json:"parentOrderId,omitempty"`
	Kind          string         `json:"kind"`
	Purpose       string         `json:"purpose"`
	Period        string         `json:"period"`
	Status        string         `json:"status"`
	Currency      string         `json:"currency"`
	Total         float64        `json:"total"`
	InvoiceNo     string         `json:"invoiceNo,omitempty"`
	Note          string         `json:"note,omitempty"`
	Error         string         `json:"error,omitempty"`
	Details       OrderDetails   `json:"details"`
	Items         []OrderItem    `json:"items"`
	Payments      []OrderPayment `json:"payments"`
	PaidTotal     float64        `json:"paidTotal"`
	CreatedAt     time.Time      `json:"createdAt"`
	UpdatedAt     time.Time      `json:"updatedAt"`
	SubmittedAt   *time.Time     `json:"submittedAt,omitempty"`
	PaidAt        *time.Time     `json:"paidAt,omitempty"`
	ApprovedAt    *time.Time     `json:"approvedAt,omitempty"`
	ActivatedAt   *time.Time     `json:"activatedAt,omitempty"`
	CancelledAt   *time.Time     `json:"cancelledAt,omitempty"`
}

type License struct {
	ID               int64     `json:"id"`
	UserID           int64     `json:"userId"`
	UserName         string    `json:"userName,omitempty"`
	OrderID          *int64    `json:"orderId,omitempty"`
	Scope            string    `json:"scope"`
	TargetID         int64     `json:"targetId"`
	TargetName       string    `json:"targetName"`
	Kind             string    `json:"kind"`
	Period           string    `json:"period"`
	Status           string    `json:"status"`
	CurrentPeriodEnd time.Time `json:"currentPeriodEnd"`
	RenewalOrderID   *int64    `json:"renewalOrderId,omitempty"`
	CancelAtEnd      bool      `json:"cancelAtPeriodEnd"`
	CreatedAt        time.Time `json:"createdAt"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type PlatformServer struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
	Kind string `json:"kind"`
}

type OrderStore interface {
	EnsureSchema(ctx context.Context) error
	ListCatalog(ctx context.Context) ([]CatalogItem, error)
	UpdateCatalogPrice(ctx context.Context, code string, monthly, annual float64) error
	Create(ctx context.Context, order Order) (Order, error)
	Save(ctx context.Context, order Order) error
	Get(ctx context.Context, id int64) (Order, error)
	List(ctx context.Context, userID int64, statuses []string) ([]Order, error)
	AddPayment(ctx context.Context, orderID int64, payment OrderPayment) error
	OpenSecrets(edge OrderEdge) OrderEdge

	SaveLicense(ctx context.Context, license License) (License, error)
	GetLicense(ctx context.Context, id int64) (License, error)
	LicenseFor(ctx context.Context, scope string, targetID int64) (License, error)
	ListLicenses(ctx context.Context, userID int64) ([]License, error)
	OwnedSiteIDs(ctx context.Context, userID int64) ([]int64, error)
	AppendLicenseEvent(ctx context.Context, event LicenseEvent) error
	ListLicenseEvents(ctx context.Context, licenseID int64) ([]LicenseEvent, error)
	ListLicenseEventsForTarget(ctx context.Context, scope string, targetID int64) ([]LicenseEvent, error)
	ListOrdersForTarget(ctx context.Context, userID int64, scope string, targetID int64) ([]Order, error)

	ListServerKinds(ctx context.Context) ([]PlatformServer, error)
	PlatformServerIDs(ctx context.Context) ([]int64, error)
	ServerKind(ctx context.Context, serverID int64) (string, error)
	SetServerKind(ctx context.Context, serverID int64, kind string) error
	SetServerExpiry(ctx context.Context, serverID int64, at time.Time) error
}

type orderStore struct {
	db  *sql.DB
	box *secretbox.Box
}

func NewOrderStore(db *sql.DB, box *secretbox.Box) OrderStore {
	return &orderStore{db: db, box: box}
}

var defaultCatalog = []struct {
	code, title, tagline string
	monthly, annual      float64
	oneTime              bool
	sort                 int
}{
	{CatalogEdgeL4, "Edge L4 protection", "Sparta network protection on your edge", 25, 240, false, 10},
	{CatalogEdgeL7, "Edge setup (L7)", "Athens on your edge for your own sites", 250, 2400, false, 11},
	{CatalogL4Addon, "L4 protection add-on", "Adds Sparta to an L7 edge", 99, 948, false, 12},
	{CatalogSiteOwn, "Site on own edge", "L7 protection for one site on your edge", 10, 96, false, 13},
	{CatalogSitePlatform, "Site on platform edge", "L7 protection for one site on Dorian edges", 20, 192, false, 14},
	{CatalogSetupFee, "Edge install fee", "One-time installation per new edge", 0, 0, true, 15},
}

func (s *orderStore) EnsureSchema(ctx context.Context) error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS orders (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) NOT NULL,
			created_by BIGINT(20) NOT NULL DEFAULT 0,
			parent_order_id BIGINT(20) DEFAULT NULL,
			kind VARCHAR(16) NOT NULL DEFAULT 'new',
			purpose VARCHAR(24) NOT NULL,
			period VARCHAR(8) NOT NULL DEFAULT 'year',
			status VARCHAR(24) NOT NULL DEFAULT 'draft',
			currency CHAR(3) NOT NULL DEFAULT 'USD',
			total DECIMAL(12,2) NOT NULL DEFAULT 0,
			invoice_no VARCHAR(32) DEFAULT NULL,
			note TEXT DEFAULT NULL,
			error_text TEXT DEFAULT NULL,
			details LONGTEXT NOT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			submitted_at DATETIME DEFAULT NULL,
			paid_at DATETIME DEFAULT NULL,
			approved_at DATETIME DEFAULT NULL,
			activated_at DATETIME DEFAULT NULL,
			cancelled_at DATETIME DEFAULT NULL,
			PRIMARY KEY (id),
			KEY idx_orders_user (user_id, status),
			KEY idx_orders_status (status)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS order_items (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			order_id BIGINT(20) NOT NULL,
			code VARCHAR(32) NOT NULL,
			label VARCHAR(128) NOT NULL DEFAULT '',
			quantity INT NOT NULL DEFAULT 1,
			unit_price DECIMAL(12,2) NOT NULL DEFAULT 0,
			line_total DECIMAL(12,2) NOT NULL DEFAULT 0,
			note VARCHAR(255) NOT NULL DEFAULT '',
			PRIMARY KEY (id),
			KEY idx_order_items_order (order_id),
			CONSTRAINT fk_order_items_order FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS order_payments (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			order_id BIGINT(20) NOT NULL,
			amount DECIMAL(12,2) NOT NULL,
			reference VARCHAR(128) NOT NULL DEFAULT '',
			paid_on DATE NOT NULL,
			recorded_by BIGINT(20) NOT NULL DEFAULT 0,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_order_payments_order (order_id),
			CONSTRAINT fk_order_payments_order FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`CREATE TABLE IF NOT EXISTS licenses (
			id BIGINT(20) NOT NULL AUTO_INCREMENT,
			user_id BIGINT(20) NOT NULL DEFAULT 0,
			order_id BIGINT(20) DEFAULT NULL,
			scope VARCHAR(8) NOT NULL,
			target_id BIGINT(20) NOT NULL,
			kind VARCHAR(16) NOT NULL,
			period VARCHAR(8) NOT NULL DEFAULT 'year',
			status VARCHAR(16) NOT NULL DEFAULT 'active',
			current_period_end DATETIME NOT NULL,
			renewal_order_id BIGINT(20) DEFAULT NULL,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY uq_licenses_target (scope, target_id),
			KEY idx_licenses_user (user_id),
			KEY idx_licenses_period_end (status, current_period_end)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
		`ALTER TABLE licenses ADD COLUMN IF NOT EXISTS cancel_at_period_end TINYINT(1) NOT NULL DEFAULT 0`,
		`ALTER TABLE servers ADD COLUMN IF NOT EXISTS kind VARCHAR(16) NOT NULL DEFAULT 'customer'`,
		`ALTER TABLE license_plans ADD COLUMN IF NOT EXISTS category VARCHAR(16) NOT NULL DEFAULT 'tier'`,
		`ALTER TABLE license_plans ADD COLUMN IF NOT EXISTS one_time TINYINT(1) NOT NULL DEFAULT 0`,
	}
	for _, stmt := range statements {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	for _, item := range defaultCatalog {
		if _, err := s.db.ExecContext(ctx, `
			INSERT INTO license_plans (id, title, tagline, badge, accent, monthly_price, annual_price, sort_order, active, category, one_time)
			VALUES (?, ?, ?, NULL, 'catalog', ?, ?, ?, 1, 'catalog', ?)
			ON DUPLICATE KEY UPDATE category = 'catalog'`,
			item.code, item.title, item.tagline, item.monthly, item.annual, item.sort, item.oneTime); err != nil {
			return err
		}
	}
	if err := s.ensureLicenseEventsSchema(ctx); err != nil {
		return err
	}
	return s.migrateLegacyLicenses(ctx)
}

// migrateLegacyLicenses creates one license per existing edge and site the first time
// the order tables are introduced, so enforcement has a row for every object.
func (s *orderStore) migrateLegacyLicenses(ctx context.Context) error {
	var licenses, orders int
	if err := s.db.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM licenses), (SELECT COUNT(*) FROM orders)`).Scan(&licenses, &orders); err != nil {
		return err
	}
	if licenses > 0 || orders > 0 {
		return nil
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT IGNORE INTO licenses (user_id, scope, target_id, kind, period, status, current_period_end)
		SELECT COALESCE((SELECT MIN(su.user_id) FROM server_users su WHERE su.server_id = s.id), 0),
		       'server', s.id,
		       CASE s.license_type WHEN 'L4' THEN 'L4' WHEN 'L7' THEN 'L7' ELSE 'Unified' END,
		       'year',
		       CASE
		         WHEN s.expired IS NULL OR s.expired >= ? THEN 'active'
		         WHEN s.expired >= ? THEN 'past_due'
		         ELSE 'expired'
		       END,
		       COALESCE(s.expired, ?)
		FROM servers s`,
		now, now.Add(-14*24*time.Hour), now.Add(365*24*time.Hour))
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT IGNORE INTO licenses (user_id, scope, target_id, kind, period, status, current_period_end)
		SELECT COALESCE((SELECT MIN(su.user_id) FROM site_servers ss JOIN server_users su ON su.server_id = ss.server_id WHERE ss.site_id = st.id), 0),
		       'site', st.id, 'SITE_OWN', 'year', 'active',
		       COALESCE((SELECT MAX(sv.expired) FROM site_servers ss JOIN servers sv ON sv.id = ss.server_id WHERE ss.site_id = st.id), ?)
		FROM sites st`,
		now.Add(365*24*time.Hour))
	return err
}

func (s *orderStore) ListCatalog(ctx context.Context) ([]CatalogItem, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, title, COALESCE(tagline, ''), monthly_price, annual_price, one_time, sort_order
		FROM license_plans
		WHERE category = 'catalog' AND active = 1
		ORDER BY sort_order, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]CatalogItem, 0, len(defaultCatalog))
	for rows.Next() {
		var item CatalogItem
		if err := rows.Scan(&item.Code, &item.Title, &item.Tagline, &item.MonthlyPrice, &item.AnnualPrice, &item.OneTime, &item.SortOrder); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *orderStore) UpdateCatalogPrice(ctx context.Context, code string, monthly, annual float64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE license_plans SET monthly_price = ?, annual_price = ? WHERE id = ? AND category = 'catalog'`, monthly, annual, code)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM license_plans WHERE id = ? AND category = 'catalog'`, code).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return errNotFound
		}
	}
	return nil
}

func (s *orderStore) sealDetails(details OrderDetails) (string, error) {
	out := details
	out.Edges = make([]OrderEdge, len(details.Edges))
	for i, edge := range details.Edges {
		for _, field := range []*string{&edge.SSHPassword, &edge.SSHPrivateKey, &edge.SSHKeyPassphrase} {
			value := strings.TrimSpace(*field)
			if value == "" || secretbox.IsSealed(value) || s.box == nil {
				continue
			}
			sealed, err := s.box.Seal(value)
			if err != nil {
				return "", err
			}
			*field = sealed
		}
		edge.HasSSHPassword = edge.SSHPassword != ""
		edge.HasSSHKey = edge.SSHPrivateKey != ""
		out.Edges[i] = edge
	}
	if out.Sites == nil {
		out.Sites = []OrderSite{}
	}
	raw, err := json.Marshal(out)
	return string(raw), err
}

// OpenSecrets decrypts the SSH credentials of one order edge for provisioning.
func (s *orderStore) OpenSecrets(edge OrderEdge) OrderEdge {
	if s.box == nil {
		return edge
	}
	for _, field := range []*string{&edge.SSHPassword, &edge.SSHPrivateKey, &edge.SSHKeyPassphrase} {
		if *field == "" {
			continue
		}
		if opened, err := s.box.Open(*field); err == nil {
			*field = opened
		}
	}
	return edge
}

func (s *orderStore) Create(ctx context.Context, order Order) (Order, error) {
	details, err := s.sealDetails(order.Details)
	if err != nil {
		return Order{}, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Order{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		INSERT INTO orders (user_id, created_by, parent_order_id, kind, purpose, period, status, currency, total, note, details)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		order.UserID, order.CreatedBy, order.ParentOrderID, order.Kind, order.Purpose, order.Period,
		order.Status, defaultCurrency(order.Currency), order.Total, nullString(order.Note), details)
	if err != nil {
		return Order{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Order{}, err
	}
	if err := replaceOrderItems(ctx, tx, id, order.Items); err != nil {
		return Order{}, err
	}
	if err := tx.Commit(); err != nil {
		return Order{}, err
	}
	return s.Get(ctx, id)
}

func (s *orderStore) Save(ctx context.Context, order Order) error {
	details, err := s.sealDetails(order.Details)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `
		UPDATE orders SET purpose = ?, period = ?, status = ?, total = ?, invoice_no = ?, note = ?, error_text = ?, details = ?,
		       submitted_at = ?, paid_at = ?, approved_at = ?, activated_at = ?, cancelled_at = ?
		WHERE id = ?`,
		order.Purpose, order.Period, order.Status, order.Total, nullString(order.InvoiceNo), nullString(order.Note),
		nullString(order.Error), details, order.SubmittedAt, order.PaidAt, order.ApprovedAt, order.ActivatedAt,
		order.CancelledAt, order.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM orders WHERE id = ?`, order.ID).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return errNotFound
		}
	}
	if err := replaceOrderItems(ctx, tx, order.ID, order.Items); err != nil {
		return err
	}
	return tx.Commit()
}

func replaceOrderItems(ctx context.Context, tx *sql.Tx, orderID int64, items []OrderItem) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM order_items WHERE order_id = ?`, orderID); err != nil {
		return err
	}
	for _, item := range items {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO order_items (order_id, code, label, quantity, unit_price, line_total, note)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			orderID, item.Code, item.Label, item.Quantity, item.UnitPrice, item.LineTotal, item.Note); err != nil {
			return err
		}
	}
	return nil
}

const orderSelect = `
	SELECT o.id, o.user_id, COALESCE(u.name, ''), COALESCE(u.email, ''), o.created_by, o.parent_order_id,
	       o.kind, o.purpose, o.period, o.status, o.currency, o.total, COALESCE(o.invoice_no, ''),
	       COALESCE(o.note, ''), COALESCE(o.error_text, ''), o.details, o.created_at, o.updated_at,
	       o.submitted_at, o.paid_at, o.approved_at, o.activated_at, o.cancelled_at
	FROM orders o
	LEFT JOIN users u ON u.id = o.user_id`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanOrder(row rowScanner) (Order, error) {
	var order Order
	var parent sql.NullInt64
	var details string
	var submitted, paid, approved, activated, cancelled sql.NullTime
	if err := row.Scan(&order.ID, &order.UserID, &order.UserName, &order.UserEmail, &order.CreatedBy, &parent,
		&order.Kind, &order.Purpose, &order.Period, &order.Status, &order.Currency, &order.Total, &order.InvoiceNo,
		&order.Note, &order.Error, &details, &order.CreatedAt, &order.UpdatedAt,
		&submitted, &paid, &approved, &activated, &cancelled); err != nil {
		return Order{}, err
	}
	if parent.Valid {
		order.ParentOrderID = &parent.Int64
	}
	order.SubmittedAt = nullTimePtr(submitted)
	order.PaidAt = nullTimePtr(paid)
	order.ApprovedAt = nullTimePtr(approved)
	order.ActivatedAt = nullTimePtr(activated)
	order.CancelledAt = nullTimePtr(cancelled)
	if strings.TrimSpace(details) != "" {
		_ = json.Unmarshal([]byte(details), &order.Details)
	}
	if order.Details.Edges == nil {
		order.Details.Edges = []OrderEdge{}
	}
	if order.Details.Sites == nil {
		order.Details.Sites = []OrderSite{}
	}
	order.Items = []OrderItem{}
	order.Payments = []OrderPayment{}
	return order, nil
}

func (s *orderStore) Get(ctx context.Context, id int64) (Order, error) {
	order, err := scanOrder(s.db.QueryRowContext(ctx, orderSelect+` WHERE o.id = ?`, id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Order{}, errNotFound
		}
		return Order{}, err
	}
	if err := s.loadOrderChildren(ctx, []*Order{&order}); err != nil {
		return Order{}, err
	}
	return order, nil
}

func (s *orderStore) List(ctx context.Context, userID int64, statuses []string) ([]Order, error) {
	query := orderSelect + ` WHERE 1 = 1`
	args := make([]any, 0, len(statuses)+1)
	if userID > 0 {
		query += ` AND o.user_id = ?`
		args = append(args, userID)
	}
	if len(statuses) > 0 {
		query += ` AND o.status IN (` + placeholders(len(statuses)) + `)`
		for _, status := range statuses {
			args = append(args, status)
		}
	}
	query += ` ORDER BY o.id DESC LIMIT 500`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	orders := make([]Order, 0)
	for rows.Next() {
		order, err := scanOrder(rows)
		if err != nil {
			return nil, err
		}
		orders = append(orders, order)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	ptrs := make([]*Order, len(orders))
	for i := range orders {
		ptrs[i] = &orders[i]
	}
	if err := s.loadOrderChildren(ctx, ptrs); err != nil {
		return nil, err
	}
	return orders, nil
}

func (s *orderStore) loadOrderChildren(ctx context.Context, orders []*Order) error {
	if len(orders) == 0 {
		return nil
	}
	byID := make(map[int64]*Order, len(orders))
	args := make([]any, 0, len(orders))
	for _, order := range orders {
		byID[order.ID] = order
		args = append(args, order.ID)
	}
	in := placeholders(len(orders))
	rows, err := s.db.QueryContext(ctx, `
		SELECT order_id, code, label, quantity, unit_price, line_total, note
		FROM order_items WHERE order_id IN (`+in+`) ORDER BY id`, args...)
	if err != nil {
		return err
	}
	for rows.Next() {
		var orderID int64
		var item OrderItem
		if err := rows.Scan(&orderID, &item.Code, &item.Label, &item.Quantity, &item.UnitPrice, &item.LineTotal, &item.Note); err != nil {
			rows.Close()
			return err
		}
		if order := byID[orderID]; order != nil {
			order.Items = append(order.Items, item)
		}
	}
	rows.Close()
	rows, err = s.db.QueryContext(ctx, `
		SELECT p.order_id, p.id, p.amount, p.reference, p.paid_on, p.recorded_by, COALESCE(u.name, ''), p.created_at
		FROM order_payments p LEFT JOIN users u ON u.id = p.recorded_by
		WHERE p.order_id IN (`+in+`) ORDER BY p.id`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var orderID int64
		var p OrderPayment
		if err := rows.Scan(&orderID, &p.ID, &p.Amount, &p.Reference, &p.PaidOn, &p.RecordedBy, &p.RecordedByName, &p.CreatedAt); err != nil {
			return err
		}
		if order := byID[orderID]; order != nil {
			order.Payments = append(order.Payments, p)
			order.PaidTotal += p.Amount
		}
	}
	return rows.Err()
}

func (s *orderStore) AddPayment(ctx context.Context, orderID int64, payment OrderPayment) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO order_payments (order_id, amount, reference, paid_on, recorded_by)
		VALUES (?, ?, ?, ?, ?)`,
		orderID, payment.Amount, payment.Reference, payment.PaidOn.Format("2006-01-02"), payment.RecordedBy)
	return err
}

const licenseSelect = `
	SELECT l.id, l.user_id, COALESCE(u.name, ''), l.order_id, l.scope, l.target_id,
	       CASE l.scope WHEN 'server' THEN COALESCE(sv.name, sv.ip, '') ELSE COALESCE(st.domain, '') END,
	       l.kind, l.period, l.status, l.current_period_end, l.renewal_order_id, l.cancel_at_period_end, l.created_at, l.updated_at
	FROM licenses l
	LEFT JOIN users u ON u.id = l.user_id
	LEFT JOIN servers sv ON l.scope = 'server' AND sv.id = l.target_id
	LEFT JOIN sites st ON l.scope = 'site' AND st.id = l.target_id`

func scanLicense(row rowScanner) (License, error) {
	var license License
	var orderID, renewalID sql.NullInt64
	if err := row.Scan(&license.ID, &license.UserID, &license.UserName, &orderID, &license.Scope, &license.TargetID,
		&license.TargetName, &license.Kind, &license.Period, &license.Status, &license.CurrentPeriodEnd,
		&renewalID, &license.CancelAtEnd, &license.CreatedAt, &license.UpdatedAt); err != nil {
		return License{}, err
	}
	if orderID.Valid {
		license.OrderID = &orderID.Int64
	}
	if renewalID.Valid {
		license.RenewalOrderID = &renewalID.Int64
	}
	return license, nil
}

// SaveLicense inserts or replaces the license of one edge or site.
func (s *orderStore) SaveLicense(ctx context.Context, license License) (License, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO licenses (user_id, order_id, scope, target_id, kind, period, status, current_period_end, renewal_order_id, cancel_at_period_end)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), order_id = VALUES(order_id), kind = VALUES(kind),
		       period = VALUES(period), status = VALUES(status), current_period_end = VALUES(current_period_end),
		       renewal_order_id = VALUES(renewal_order_id), cancel_at_period_end = VALUES(cancel_at_period_end)`,
		license.UserID, license.OrderID, license.Scope, license.TargetID, license.Kind, license.Period,
		license.Status, license.CurrentPeriodEnd.UTC(), license.RenewalOrderID, license.CancelAtEnd)
	if err != nil {
		return License{}, err
	}
	return s.LicenseFor(ctx, license.Scope, license.TargetID)
}

func (s *orderStore) GetLicense(ctx context.Context, id int64) (License, error) {
	license, err := scanLicense(s.db.QueryRowContext(ctx, licenseSelect+` WHERE l.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return License{}, errNotFound
	}
	return license, err
}

func (s *orderStore) LicenseFor(ctx context.Context, scope string, targetID int64) (License, error) {
	license, err := scanLicense(s.db.QueryRowContext(ctx, licenseSelect+` WHERE l.scope = ? AND l.target_id = ?`, scope, targetID))
	if errors.Is(err, sql.ErrNoRows) {
		return License{}, errNotFound
	}
	return license, err
}

func (s *orderStore) ListLicenses(ctx context.Context, userID int64) ([]License, error) {
	query := licenseSelect
	args := []any{}
	if userID > 0 {
		query += ` WHERE l.user_id = ?`
		args = append(args, userID)
	}
	query += ` ORDER BY l.current_period_end, l.id`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]License, 0)
	for rows.Next() {
		license, err := scanLicense(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, license)
	}
	return out, rows.Err()
}

func (s *orderStore) OwnedSiteIDs(ctx context.Context, userID int64) ([]int64, error) {
	return s.queryIDs(ctx, `SELECT target_id FROM licenses WHERE scope = 'site' AND user_id = ? AND status <> 'cancelled'`, userID)
}

func (s *orderStore) ListServerKinds(ctx context.Context) ([]PlatformServer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, COALESCE(name, ''), COALESCE(ip, ''), kind FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PlatformServer, 0)
	for rows.Next() {
		var item PlatformServer
		if err := rows.Scan(&item.ID, &item.Name, &item.IP, &item.Kind); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *orderStore) PlatformServerIDs(ctx context.Context) ([]int64, error) {
	return s.queryIDs(ctx, `SELECT id FROM servers WHERE kind = 'platform' ORDER BY id`)
}

func (s *orderStore) ServerKind(ctx context.Context, serverID int64) (string, error) {
	var kind string
	err := s.db.QueryRowContext(ctx, `SELECT kind FROM servers WHERE id = ?`, serverID).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNotFound
	}
	return kind, err
}

func (s *orderStore) SetServerKind(ctx context.Context, serverID int64, kind string) error {
	if kind != ServerKindPlatform && kind != ServerKindCustomer {
		return fmt.Errorf("invalid server kind %q", kind)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE servers SET kind = ? WHERE id = ?`, kind, serverID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		if _, err := s.ServerKind(ctx, serverID); err != nil {
			return err
		}
	}
	return nil
}

func (s *orderStore) SetServerExpiry(ctx context.Context, serverID int64, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET expired = ? WHERE id = ?`, at.UTC(), serverID)
	return err
}

func (s *orderStore) queryIDs(ctx context.Context, query string, args ...any) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]int64, 0)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

func nullString(value string) sql.NullString {
	value = strings.TrimSpace(value)
	return sql.NullString{String: value, Valid: value != ""}
}

func nullTimePtr(value sql.NullTime) *time.Time {
	if !value.Valid {
		return nil
	}
	t := value.Time
	return &t
}

func defaultCurrency(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	if len(value) != 3 {
		return "USD"
	}
	return value
}
