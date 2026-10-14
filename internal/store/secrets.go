package store

import (
	"context"
	"database/sql"
	"fmt"

	"vue-project-backend/internal/secretbox"
)

// sealLegacyColumn encrypts every non-empty value of table.column that is not
// yet sealed. table and column are compile-time constants, never user input.
func sealLegacyColumn(ctx context.Context, db *sql.DB, box *secretbox.Box, table, column string) (int, error) {
	rows, err := db.QueryContext(ctx, fmt.Sprintf(
		"SELECT id, `%[2]s` FROM `%[1]s` WHERE `%[2]s` IS NOT NULL AND `%[2]s` <> '' AND `%[2]s` NOT LIKE 'enc:v1:%%'",
		table, column))
	if err != nil {
		return 0, err
	}
	type legacy struct {
		id    int64
		plain string
	}
	var pending []legacy
	for rows.Next() {
		var item legacy
		if err := rows.Scan(&item.id, &item.plain); err != nil {
			rows.Close()
			return 0, err
		}
		pending = append(pending, item)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	update := fmt.Sprintf("UPDATE `%[1]s` SET `%[2]s` = ? WHERE id = ? AND `%[2]s` = ?", table, column)
	migrated := 0
	for _, item := range pending {
		sealed, err := box.Seal(item.plain)
		if err != nil {
			return migrated, err
		}
		if _, err := db.ExecContext(ctx, update, sealed, item.id, item.plain); err != nil {
			return migrated, fmt.Errorf("seal %s.%s id=%d: %w", table, column, item.id, err)
		}
		migrated++
	}
	return migrated, nil
}
