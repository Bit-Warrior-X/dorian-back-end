package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"
)

type Site struct {
	ID                int64      `json:"id"`
	Domain            string     `json:"domain"`
	Status            string     `json:"status"`
	WafID             *int64     `json:"wafId,omitempty"`
	WafName           string     `json:"wafName,omitempty"`
	WafRole           string     `json:"wafRole,omitempty"`
	CertificateStatus string     `json:"certificateStatus"`
	CertificateExpiry *time.Time `json:"certificateExpiry,omitempty"`
	CertificateError  string     `json:"certificateError,omitempty"`
	CacheRatio        float64    `json:"cacheRatio"`
	Bandwidth         int64      `json:"bandwidth"`
	SslType           string     `json:"sslType"`
	SslCert           string     `json:"sslCert,omitempty"`
	SslCertKey        string     `json:"sslCertKey,omitempty"`
	CreatedAt         time.Time  `json:"createdAt"`
	UpdatedAt         time.Time  `json:"updatedAt"`
	ServerIDs         []int64    `json:"serverIds"`
	Servers           []string   `json:"servers"`
}

type SiteInput struct {
	Domain            string  `json:"domain"`
	Status            string  `json:"status"`
	WafID             *int64  `json:"wafId"`
	CertificateStatus string  `json:"certificateStatus"`
	CertificateExpiry *string `json:"certificateExpiry"`
	CacheRatio        float64 `json:"cacheRatio"`
	Bandwidth         int64   `json:"bandwidth"`
	SslType           string  `json:"sslType"`
	SslCert           string  `json:"sslCert"`
	SslCertKey        string  `json:"sslCertKey"`
	ServerIDs         []int64 `json:"serverIds"`
}

func (input SiteInput) Normalize() SiteInput {
	return SiteInput{
		Domain:            strings.ToLower(strings.TrimSpace(input.Domain)),
		Status:            strings.TrimSpace(input.Status),
		WafID:             input.WafID,
		CertificateStatus: strings.TrimSpace(input.CertificateStatus),
		CertificateExpiry: input.CertificateExpiry,
		CacheRatio:        input.CacheRatio,
		Bandwidth:         input.Bandwidth,
		SslType:           strings.TrimSpace(input.SslType),
		SslCert:           strings.TrimSpace(input.SslCert),
		SslCertKey:        strings.TrimSpace(input.SslCertKey),
		ServerIDs:         uniqueInt64(input.ServerIDs),
	}
}

type SiteStore interface {
	List(ctx context.Context) ([]Site, error)
	Count(ctx context.Context) (int64, error)
	CountActive(ctx context.Context) (int64, error)
	Get(ctx context.Context, id int64) (Site, error)
	Create(ctx context.Context, input SiteInput) (Site, error)
	Update(ctx context.Context, id int64, input SiteInput) (Site, error)
	UpdateCertificate(ctx context.Context, id int64, certPEM, keyPEM, status string, expiry *time.Time) error
	UpdateCertificateStatus(ctx context.Context, id int64, status, errMsg string) error
	Delete(ctx context.Context, id int64) error
	UpdateSiteServers(ctx context.Context, siteID int64, serverIDs []int64) error
	EnsureWafRule(ctx context.Context, siteID int64, wafRules WafRuleStore) (int64, error)
	WafRuleIDForWrite(ctx context.Context, siteID int64, wafRules WafRuleStore) (int64, error)
	ForkPredefinedWafForSite(ctx context.Context, siteID int64, wafRules WafRuleStore) (Site, error)
}

type siteStore struct {
	db *sql.DB
}

func NewSiteStore(db *sql.DB) SiteStore {
	return &siteStore{db: db}
}

const siteSelectColumns = `
	s.id, s.domain, s.status, s.waf_id, wr.name AS waf_name, wr.role AS waf_role,
	s.certificate_status, s.certificate_expiry, s.certificate_error,
	s.cache_ratio, s.bandwidth, s.ssl_type, s.ssl_cert, s.ssl_cert_key,
	s.created_at, s.updated_at`

func (store *siteStore) scanSite(row interface {
	Scan(dest ...any) error
}) (Site, error) {
	var item Site
	var wafID sql.NullInt64
	var wafName sql.NullString
	var wafRole sql.NullString
	var certExpiry sql.NullTime
	var certError sql.NullString
	var sslCert sql.NullString
	var sslCertKey sql.NullString

	if err := row.Scan(
		&item.ID,
		&item.Domain,
		&item.Status,
		&wafID,
		&wafName,
		&wafRole,
		&item.CertificateStatus,
		&certExpiry,
		&certError,
		&item.CacheRatio,
		&item.Bandwidth,
		&item.SslType,
		&sslCert,
		&sslCertKey,
		&item.CreatedAt,
		&item.UpdatedAt,
	); err != nil {
		return Site{}, err
	}

	if wafID.Valid {
		item.WafID = &wafID.Int64
	}
	if wafName.Valid {
		item.WafName = wafName.String
	}
	if wafRole.Valid {
		item.WafRole = wafRole.String
	}
	if certExpiry.Valid {
		t := certExpiry.Time
		item.CertificateExpiry = &t
	}
	if certError.Valid {
		item.CertificateError = certError.String
	}
	if sslCert.Valid {
		item.SslCert = sslCert.String
	}
	if sslCertKey.Valid {
		item.SslCertKey = sslCertKey.String
	}

	return item, nil
}

func (store *siteStore) List(ctx context.Context) ([]Site, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT `+siteSelectColumns+`
		FROM sites s
		LEFT JOIN waf_rule wr ON wr.id = s.waf_id
		ORDER BY s.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sites []Site
	siteIDs := make([]int64, 0)
	for rows.Next() {
		item, err := store.scanSite(rows)
		if err != nil {
			return nil, err
		}
		siteIDs = append(siteIDs, item.ID)
		sites = append(sites, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(sites) == 0 {
		return sites, nil
	}

	serverMap, err := store.siteServers(ctx, siteIDs)
	if err != nil {
		return nil, err
	}

	for i := range sites {
		ref := serverMap[sites[i].ID]
		sites[i].ServerIDs = ref.ids
		sites[i].Servers = ref.names
	}

	return sites, nil
}

func (store *siteStore) Count(ctx context.Context) (int64, error) {
	var count int64
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites`).Scan(&count)
	return count, err
}

func (store *siteStore) CountActive(ctx context.Context) (int64, error) {
	var count int64
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sites WHERE UPPER(status) = 'ENABLE'`).Scan(&count)
	return count, err
}

func (store *siteStore) Get(ctx context.Context, id int64) (Site, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT `+siteSelectColumns+`
		FROM sites s
		LEFT JOIN waf_rule wr ON wr.id = s.waf_id
		WHERE s.id = ?
		LIMIT 1`, id)

	item, err := store.scanSite(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Site{}, errNotFound
		}
		return Site{}, err
	}

	serverMap, err := store.siteServers(ctx, []int64{id})
	if err != nil {
		return Site{}, err
	}
	ref := serverMap[id]
	item.ServerIDs = ref.ids
	item.Servers = ref.names

	return item, nil
}

func (store *siteStore) Create(ctx context.Context, input SiteInput) (Site, error) {
	input = normalizeSiteSslInput(input)
	certExpiry, err := parseOptionalDateTime(input.CertificateExpiry)
	if err != nil {
		return Site{}, err
	}

	result, err := store.db.ExecContext(ctx, `
		INSERT INTO sites (
			domain, status, waf_id, certificate_status, certificate_expiry,
			cache_ratio, bandwidth, ssl_type, ssl_cert, ssl_cert_key
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		input.Domain,
		coalesceSiteStatus(input.Status),
		nullableInt64(input.WafID),
		coalesceSiteCertStatus(input.CertificateStatus),
		certExpiry,
		input.CacheRatio,
		input.Bandwidth,
		coalesceSiteSslType(input.SslType),
		nullableString(input.SslCert),
		nullableString(input.SslCertKey),
	)
	if err != nil {
		return Site{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return Site{}, err
	}

	return store.Get(ctx, id)
}

func (store *siteStore) Update(ctx context.Context, id int64, input SiteInput) (Site, error) {
	input = normalizeSiteSslInput(input)
	certExpiry, err := parseOptionalDateTime(input.CertificateExpiry)
	if err != nil {
		return Site{}, err
	}

	clearError := coalesceSiteSslType(input.SslType) == "none"
	query := `
		UPDATE sites
		SET domain = ?, status = ?, waf_id = ?, certificate_status = ?, certificate_expiry = ?,
			cache_ratio = ?, bandwidth = ?, ssl_type = ?, ssl_cert = ?, ssl_cert_key = ?
		WHERE id = ?`
	args := []any{
		input.Domain,
		coalesceSiteStatus(input.Status),
		nullableInt64(input.WafID),
		coalesceSiteCertStatus(input.CertificateStatus),
		certExpiry,
		input.CacheRatio,
		input.Bandwidth,
		coalesceSiteSslType(input.SslType),
		nullableString(input.SslCert),
		nullableString(input.SslCertKey),
		id,
	}
	if clearError {
		query = `
			UPDATE sites
			SET domain = ?, status = ?, waf_id = ?, certificate_status = ?, certificate_expiry = ?,
				certificate_error = NULL,
				cache_ratio = ?, bandwidth = ?, ssl_type = ?, ssl_cert = ?, ssl_cert_key = ?
			WHERE id = ?`
	}

	result, err := store.db.ExecContext(ctx, query, args...)
	if err != nil {
		return Site{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return Site{}, err
	}
	if affected == 0 {
		exists, err := store.siteExists(ctx, id)
		if err != nil {
			return Site{}, err
		}
		if !exists {
			return Site{}, errNotFound
		}
	}

	return store.Get(ctx, id)
}

func normalizeSiteSslInput(input SiteInput) SiteInput {
	sslType := coalesceSiteSslType(input.SslType)
	input.SslType = sslType
	if sslType == "none" {
		input.CertificateStatus = "none"
		input.CertificateExpiry = nil
		input.SslCert = ""
		input.SslCertKey = ""
	}
	return input
}

func (store *siteStore) UpdateCertificate(ctx context.Context, id int64, certPEM, keyPEM, status string, expiry *time.Time) error {
	result, err := store.db.ExecContext(ctx, `
		UPDATE sites
		SET ssl_cert = ?, ssl_cert_key = ?, certificate_status = ?, certificate_expiry = ?, certificate_error = NULL
		WHERE id = ?`,
		nullableString(certPEM),
		nullableString(keyPEM),
		coalesceSiteCertStatus(status),
		nullTime(expiry),
		id,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		exists, err := store.siteExists(ctx, id)
		if err != nil {
			return err
		}
		if !exists {
			return errNotFound
		}
	}
	return nil
}

func (store *siteStore) UpdateCertificateStatus(ctx context.Context, id int64, status, errMsg string) error {
	result, err := store.db.ExecContext(ctx, `
		UPDATE sites
		SET certificate_status = ?, certificate_error = ?
		WHERE id = ?`,
		coalesceSiteCertStatus(status),
		nullableString(strings.TrimSpace(errMsg)),
		id,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		exists, err := store.siteExists(ctx, id)
		if err != nil {
			return err
		}
		if !exists {
			return errNotFound
		}
	}
	return nil
}

func (store *siteStore) Delete(ctx context.Context, id int64) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM sites WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return errNotFound
	}
	return nil
}

func (store *siteStore) siteExists(ctx context.Context, id int64) (bool, error) {
	var exists int
	row := store.db.QueryRowContext(ctx, `SELECT 1 FROM sites WHERE id = ?`, id)
	if err := row.Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (store *siteStore) UpdateSiteServers(ctx context.Context, siteID int64, serverIDs []int64) error {
	uniqueIDs := uniqueInt64(serverIDs)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM site_servers WHERE site_id = ?`, siteID); err != nil {
		_ = tx.Rollback()
		return err
	}

	for _, serverID := range uniqueIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO site_servers (site_id, server_id)
			VALUES (?, ?)`,
			siteID,
			serverID,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

func (store *siteStore) siteServers(ctx context.Context, siteIDs []int64) (map[int64]serverRefs, error) {
	ids := uniqueInt64(siteIDs)
	if len(ids) == 0 {
		return map[int64]serverRefs{}, nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}

	query := fmt.Sprintf(`
		SELECT ss.site_id, s.id, s.name
		FROM site_servers ss
		JOIN servers s ON s.id = ss.server_id
		WHERE ss.site_id IN (%s)
		ORDER BY s.name`, strings.Join(placeholders, ","))

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64]serverRefs{}
	for rows.Next() {
		var siteID int64
		var serverID int64
		var name sql.NullString
		if err := rows.Scan(&siteID, &serverID, &name); err != nil {
			return nil, err
		}
		entry := result[siteID]
		entry.ids = append(entry.ids, serverID)
		if name.Valid && strings.TrimSpace(name.String) != "" {
			entry.names = append(entry.names, name.String)
		} else {
			entry.names = append(entry.names, fmt.Sprintf("Server #%d", serverID))
		}
		result[siteID] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

var errPredefinedWafRequiresFork = errors.New("predefined waf rule must be forked before editing")

func IsPredefinedWafRequiresFork(err error) bool {
	return errors.Is(err, errPredefinedWafRequiresFork)
}

func (store *siteStore) EnsureWafRule(ctx context.Context, siteID int64, wafRules WafRuleStore) (int64, error) {
	site, err := store.Get(ctx, siteID)
	if err != nil {
		return 0, err
	}
	if site.WafID != nil && *site.WafID > 0 {
		return *site.WafID, nil
	}

	created, err := wafRules.Create(ctx, WafRuleInput{
		Name: fmt.Sprintf("%s WAF", site.Domain),
		Role: "custom",
	})
	if err != nil {
		return 0, err
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE sites SET waf_id = ? WHERE id = ?`, created.ID, siteID); err != nil {
		return 0, err
	}

	return created.ID, nil
}

func (store *siteStore) WafRuleIDForWrite(ctx context.Context, siteID int64, wafRules WafRuleStore) (int64, error) {
	site, err := store.Get(ctx, siteID)
	if err != nil {
		return 0, err
	}
	if site.WafID != nil && *site.WafID > 0 {
		rule, err := wafRules.Get(ctx, *site.WafID)
		if err != nil {
			return 0, err
		}
		if strings.EqualFold(rule.Role, "predefined") {
			return 0, errPredefinedWafRequiresFork
		}
		return *site.WafID, nil
	}

	return store.EnsureWafRule(ctx, siteID, wafRules)
}

func (store *siteStore) ForkPredefinedWafForSite(ctx context.Context, siteID int64, wafRules WafRuleStore) (Site, error) {
	site, err := store.Get(ctx, siteID)
	if err != nil {
		return Site{}, err
	}
	if site.WafID == nil || *site.WafID <= 0 {
		return Site{}, errors.New("site has no waf rule to fork")
	}

	rule, err := wafRules.Get(ctx, *site.WafID)
	if err != nil {
		return Site{}, err
	}
	if !strings.EqualFold(rule.Role, "predefined") {
		return site, nil
	}

	copyName := strings.TrimSpace(fmt.Sprintf("%s - %s", rule.Name, site.Domain))
	if copyName == "" || copyName == "-" {
		copyName = fmt.Sprintf("%s WAF", site.Domain)
	}

	dup, err := wafRules.Duplicate(ctx, *site.WafID, copyName)
	if err != nil {
		return Site{}, err
	}

	if _, err := store.db.ExecContext(ctx, `UPDATE sites SET waf_id = ? WHERE id = ?`, dup.ID, siteID); err != nil {
		return Site{}, err
	}

	return store.Get(ctx, siteID)
}

func IsDuplicateDomain(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	return false
}

func coalesceSiteStatus(value string) string {
	if strings.EqualFold(value, "DISABLE") {
		return "DISABLE"
	}
	return "ENABLE"
}

func coalesceSiteCertStatus(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "valid", "expiring", "expired", "none", "pending", "queued", "dns", "validating", "syncing", "failed":
		return trimmed
	default:
		return "none"
	}
}

func coalesceSiteSslType(value string) string {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	switch trimmed {
	case "none", "managed", "custom", "letsencrypt", "zerossl", "googletrust":
		return trimmed
	default:
		return "none"
	}
}

func nullTime(value *time.Time) sql.NullTime {
	if value == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *value, Valid: true}
}

func nullableInt64(value *int64) sql.NullInt64 {
	if value == nil {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Int64: *value, Valid: true}
}

func parseOptionalDateTime(value *string) (sql.NullTime, error) {
	if value == nil {
		return sql.NullTime{Valid: false}, nil
	}
	trimmed := strings.TrimSpace(*value)
	if trimmed == "" {
		return sql.NullTime{Valid: false}, nil
	}
	layouts := []string{
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, trimmed); err == nil {
			return sql.NullTime{Time: parsed, Valid: true}, nil
		}
	}
	return sql.NullTime{}, fmt.Errorf("invalid certificate expiry format")
}
