package store

import (
	"context"
	"database/sql"
)

// LicensePlan is a priced license tier row from license_plans.
type LicensePlan struct {
	ID           string  `json:"id"`
	Title        string  `json:"title"`
	Tagline      string  `json:"tagline,omitempty"`
	Badge        *string `json:"badge"`
	Accent       string  `json:"accent"`
	MonthlyPrice float64 `json:"monthlyPrice"`
	AnnualPrice  float64 `json:"annualPrice"`
	SortOrder    int     `json:"sortOrder"`
}

type LicensePlanStore interface {
	ListActive(ctx context.Context) ([]LicensePlan, error)
}

type licensePlanStore struct {
	db *sql.DB
}

func NewLicensePlanStore(db *sql.DB) LicensePlanStore {
	return &licensePlanStore{db: db}
}

func (store *licensePlanStore) ListActive(ctx context.Context) ([]LicensePlan, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, title, COALESCE(tagline, ''), badge, accent,
		       monthly_price, annual_price, sort_order
		FROM license_plans
		WHERE active = 1
		ORDER BY sort_order ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	plans := make([]LicensePlan, 0)
	for rows.Next() {
		var plan LicensePlan
		var badge sql.NullString
		if scanErr := rows.Scan(
			&plan.ID,
			&plan.Title,
			&plan.Tagline,
			&badge,
			&plan.Accent,
			&plan.MonthlyPrice,
			&plan.AnnualPrice,
			&plan.SortOrder,
		); scanErr != nil {
			return nil, scanErr
		}
		if badge.Valid && badge.String != "" {
			b := badge.String
			plan.Badge = &b
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}
