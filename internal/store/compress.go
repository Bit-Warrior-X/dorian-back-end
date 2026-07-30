package store

import (
	"context"
	"database/sql"
	"errors"
)

type CompressSettings struct {
	ID           int64 `json:"id"`
	SiteID     int64 `json:"siteId"`
	CSS          bool  `json:"css"`
	HTML         bool  `json:"html"`
	JS           bool  `json:"js"`
	Audio        bool  `json:"audio"`
	Font         bool  `json:"font"`
	Applications bool  `json:"applications"`
}

type CompressSettingsInput struct {
	CSS          bool
	HTML         bool
	JS           bool
	Audio        bool
	Font         bool
	Applications bool
}

type CompressStore interface {
	GetOrCreateBySiteID(ctx context.Context, siteID int64) (CompressSettings, error)
	UpsertBySiteID(ctx context.Context, siteID int64, input CompressSettingsInput) (CompressSettings, error)
}

type compressStore struct {
	db *sql.DB
}

func NewCompressStore(db *sql.DB) CompressStore {
	return &compressStore{db: db}
}

func defaultCompressSettings(siteID int64) CompressSettings {
	return CompressSettings{
		SiteID:     siteID,
		CSS:          true,
		HTML:         true,
		JS:           true,
		Audio:        false,
		Font:         false,
		Applications: false,
	}
}

func (store *compressStore) GetOrCreateBySiteID(ctx context.Context, siteID int64) (CompressSettings, error) {
	settings, err := store.getBySiteID(ctx, siteID)
	if err == nil {
		return settings, nil
	}
	if !errors.Is(err, errNotFound) {
		return CompressSettings{}, err
	}

	defaults := defaultCompressSettings(siteID)
	created, err := store.insert(ctx, siteID, CompressSettingsInput{
		CSS:          defaults.CSS,
		HTML:         defaults.HTML,
		JS:           defaults.JS,
		Audio:        defaults.Audio,
		Font:         defaults.Font,
		Applications: defaults.Applications,
	})
	if err != nil {
		// Concurrent create: return the existing row.
		existing, getErr := store.getBySiteID(ctx, siteID)
		if getErr == nil {
			return existing, nil
		}
		return CompressSettings{}, err
	}
	return created, nil
}

func (store *compressStore) UpsertBySiteID(ctx context.Context, siteID int64, input CompressSettingsInput) (CompressSettings, error) {
	existing, err := store.getBySiteID(ctx, siteID)
	if err == nil {
		return store.update(ctx, siteID, existing.ID, input)
	}
	if !errors.Is(err, errNotFound) {
		return CompressSettings{}, err
	}
	return store.insert(ctx, siteID, input)
}

func (store *compressStore) getBySiteID(ctx context.Context, siteID int64) (CompressSettings, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT id, site_id, css, html, js, audio, font, applications
		FROM compress_settings
		WHERE site_id = ?`, siteID)

	var settings CompressSettings
	var css, html, js, audio, font, applications int
	if err := row.Scan(
		&settings.ID,
		&settings.SiteID,
		&css,
		&html,
		&js,
		&audio,
		&font,
		&applications,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return CompressSettings{}, errNotFound
		}
		return CompressSettings{}, err
	}

	settings.CSS = css != 0
	settings.HTML = html != 0
	settings.JS = js != 0
	settings.Audio = audio != 0
	settings.Font = font != 0
	settings.Applications = applications != 0
	return settings, nil
}

func (store *compressStore) insert(ctx context.Context, siteID int64, input CompressSettingsInput) (CompressSettings, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO compress_settings (site_id, css, html, js, audio, font, applications)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		siteID,
		boolToTinyInt(input.CSS),
		boolToTinyInt(input.HTML),
		boolToTinyInt(input.JS),
		boolToTinyInt(input.Audio),
		boolToTinyInt(input.Font),
		boolToTinyInt(input.Applications),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return CompressSettings{}, errNotFound
		}
		return CompressSettings{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return CompressSettings{}, err
	}

	return CompressSettings{
		ID:           id,
		SiteID:     siteID,
		CSS:          input.CSS,
		HTML:         input.HTML,
		JS:           input.JS,
		Audio:        input.Audio,
		Font:         input.Font,
		Applications: input.Applications,
	}, nil
}

func (store *compressStore) update(ctx context.Context, siteID, id int64, input CompressSettingsInput) (CompressSettings, error) {
	// Do not treat RowsAffected == 0 as missing: MySQL returns 0 when SET
	// values are identical to the current row.
	_, err := store.db.ExecContext(ctx, `
		UPDATE compress_settings
		SET css = ?, html = ?, js = ?, audio = ?, font = ?, applications = ?
		WHERE id = ? AND site_id = ?`,
		boolToTinyInt(input.CSS),
		boolToTinyInt(input.HTML),
		boolToTinyInt(input.JS),
		boolToTinyInt(input.Audio),
		boolToTinyInt(input.Font),
		boolToTinyInt(input.Applications),
		id,
		siteID,
	)
	if err != nil {
		return CompressSettings{}, err
	}

	return CompressSettings{
		ID:           id,
		SiteID:     siteID,
		CSS:          input.CSS,
		HTML:         input.HTML,
		JS:           input.JS,
		Audio:        input.Audio,
		Font:         input.Font,
		Applications: input.Applications,
	}, nil
}

func boolToTinyInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
