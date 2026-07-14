package store

import (
	"context"
	"database/sql"
	"errors"
)

type CompressSettings struct {
	ID           int64 `json:"id"`
	ServerID     int64 `json:"serverId"`
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
	GetOrCreateByServerID(ctx context.Context, serverID int64) (CompressSettings, error)
	UpsertByServerID(ctx context.Context, serverID int64, input CompressSettingsInput) (CompressSettings, error)
}

type compressStore struct {
	db *sql.DB
}

func NewCompressStore(db *sql.DB) CompressStore {
	return &compressStore{db: db}
}

func defaultCompressSettings(serverID int64) CompressSettings {
	return CompressSettings{
		ServerID:     serverID,
		CSS:          true,
		HTML:         true,
		JS:           true,
		Audio:        false,
		Font:         false,
		Applications: false,
	}
}

func (store *compressStore) GetOrCreateByServerID(ctx context.Context, serverID int64) (CompressSettings, error) {
	settings, err := store.getByServerID(ctx, serverID)
	if err == nil {
		return settings, nil
	}
	if !errors.Is(err, errNotFound) {
		return CompressSettings{}, err
	}

	defaults := defaultCompressSettings(serverID)
	created, err := store.insert(ctx, serverID, CompressSettingsInput{
		CSS:          defaults.CSS,
		HTML:         defaults.HTML,
		JS:           defaults.JS,
		Audio:        defaults.Audio,
		Font:         defaults.Font,
		Applications: defaults.Applications,
	})
	if err != nil {
		// Concurrent create: return the existing row.
		existing, getErr := store.getByServerID(ctx, serverID)
		if getErr == nil {
			return existing, nil
		}
		return CompressSettings{}, err
	}
	return created, nil
}

func (store *compressStore) UpsertByServerID(ctx context.Context, serverID int64, input CompressSettingsInput) (CompressSettings, error) {
	existing, err := store.getByServerID(ctx, serverID)
	if err == nil {
		return store.update(ctx, serverID, existing.ID, input)
	}
	if !errors.Is(err, errNotFound) {
		return CompressSettings{}, err
	}
	return store.insert(ctx, serverID, input)
}

func (store *compressStore) getByServerID(ctx context.Context, serverID int64) (CompressSettings, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT id, server_id, css, html, js, audio, font, applications
		FROM compress_settings
		WHERE server_id = ?`, serverID)

	var settings CompressSettings
	var css, html, js, audio, font, applications int
	if err := row.Scan(
		&settings.ID,
		&settings.ServerID,
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

func (store *compressStore) insert(ctx context.Context, serverID int64, input CompressSettingsInput) (CompressSettings, error) {
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO compress_settings (server_id, css, html, js, audio, font, applications)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		serverID,
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
		ServerID:     serverID,
		CSS:          input.CSS,
		HTML:         input.HTML,
		JS:           input.JS,
		Audio:        input.Audio,
		Font:         input.Font,
		Applications: input.Applications,
	}, nil
}

func (store *compressStore) update(ctx context.Context, serverID, id int64, input CompressSettingsInput) (CompressSettings, error) {
	// Do not treat RowsAffected == 0 as missing: MySQL returns 0 when SET
	// values are identical to the current row.
	_, err := store.db.ExecContext(ctx, `
		UPDATE compress_settings
		SET css = ?, html = ?, js = ?, audio = ?, font = ?, applications = ?
		WHERE id = ? AND server_id = ?`,
		boolToTinyInt(input.CSS),
		boolToTinyInt(input.HTML),
		boolToTinyInt(input.JS),
		boolToTinyInt(input.Audio),
		boolToTinyInt(input.Font),
		boolToTinyInt(input.Applications),
		id,
		serverID,
	)
	if err != nil {
		return CompressSettings{}, err
	}

	return CompressSettings{
		ID:           id,
		ServerID:     serverID,
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
