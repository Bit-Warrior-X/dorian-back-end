package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/go-sql-driver/mysql"
)

type User struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Role      string   `json:"role"`
	Status    string   `json:"status"`
	ServerIDs []int64  `json:"serverIds"`
	Servers   []string `json:"servers"`
}

type UserInput struct {
	Name      string  `json:"name"`
	Email     string  `json:"email"`
	Password  string  `json:"password"`
	Role      string  `json:"role"`
	Status    string  `json:"status"`
	ServerIDs []int64 `json:"serverIds"`
}

func (input UserInput) Normalize() UserInput {
	return UserInput{
		Name:      strings.TrimSpace(input.Name),
		Email:     strings.ToLower(strings.TrimSpace(input.Email)),
		Password:  strings.TrimSpace(input.Password),
		Role:      strings.TrimSpace(input.Role),
		Status:    strings.TrimSpace(input.Status),
		ServerIDs: uniqueInt64(input.ServerIDs),
	}
}

type UserStore interface {
	List(ctx context.Context) ([]User, error)
	Count(ctx context.Context) (int64, error)
	FindByID(ctx context.Context, id int64) (User, error)
	FindByCredentials(ctx context.Context, email, password string) (User, error)
	Create(ctx context.Context, input UserInput) (User, error)
	Update(ctx context.Context, id int64, input UserInput) (User, error)
	Delete(ctx context.Context, id int64) error
	UpdateUserServers(ctx context.Context, userID int64, serverIDs []int64) error
}

type userStore struct {
	db *sql.DB
}

func NewUserStore(db *sql.DB) UserStore {
	return &userStore{db: db}
}

func (store *userStore) List(ctx context.Context) ([]User, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, name, email, password, role, status
		FROM users
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	userIDs := make([]int64, 0)
	for rows.Next() {
		var item User
		if err := rows.Scan(&item.ID, &item.Name, &item.Email, &item.Password, &item.Role, &item.Status); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, item.ID)
		users = append(users, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return users, nil
	}

	serverMap, err := store.userServers(ctx, userIDs)
	if err != nil {
		return nil, err
	}

	for i := range users {
		ref := serverMap[users[i].ID]
		users[i].ServerIDs = ref.ids
		users[i].Servers = ref.names
	}

	return users, nil
}

func (store *userStore) Count(ctx context.Context) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *userStore) FindByID(ctx context.Context, id int64) (User, error) {
	var user User
	row := store.db.QueryRowContext(ctx, `
		SELECT id, name, email, password, role, status
		FROM users
		WHERE id = ?
		LIMIT 1`, id)
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Role, &user.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, errNotFound
		}
		return User{}, err
	}
	serverMap, err := store.userServers(ctx, []int64{user.ID})
	if err != nil {
		return User{}, err
	}
	ref := serverMap[user.ID]
	user.ServerIDs = ref.ids
	user.Servers = ref.names
	return user, nil
}

func (store *userStore) FindByCredentials(ctx context.Context, email, password string) (User, error) {
	var user User
	row := store.db.QueryRowContext(ctx, `
		SELECT id, name, email, password, role, status
		FROM users
		WHERE email = ? AND password = ?
		LIMIT 1`,
		email,
		password,
	)
	if err := row.Scan(&user.ID, &user.Name, &user.Email, &user.Password, &user.Role, &user.Status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return User{}, errNotFound
		}
		return User{}, err
	}
	return user, nil
}

func (store *userStore) Create(ctx context.Context, input UserInput) (User, error) {
	password := nullableString(input.Password)
	result, err := store.db.ExecContext(ctx, `
		INSERT INTO users (name, email, password, role, status)
		VALUES (?, ?, ?, ?, ?)`,
		input.Name,
		input.Email,
		password,
		coalesce(input.Role, "User"),
		coalesce(input.Status, "Waiting"),
	)
	if err != nil {
		return User{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return User{}, err
	}

	return User{
		ID:       id,
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
		Role:     coalesce(input.Role, "User"),
		Status:   coalesce(input.Status, "Waiting"),
	}, nil
}

func (store *userStore) Update(ctx context.Context, id int64, input UserInput) (User, error) {
	password := nullableString(input.Password)
	result, err := store.db.ExecContext(ctx, `
		UPDATE users
		SET name = ?, email = ?, password = ?, role = ?, status = ?
		WHERE id = ?`,
		input.Name,
		input.Email,
		password,
		coalesce(input.Role, "User"),
		coalesce(input.Status, "Waiting"),
		id,
	)
	if err != nil {
		return User{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return User{}, err
	}
	if affected == 0 {
		exists, err := store.userExists(ctx, id)
		if err != nil {
			return User{}, err
		}
		if !exists {
			return User{}, errNotFound
		}
	}

	return User{
		ID:       id,
		Name:     input.Name,
		Email:    input.Email,
		Password: input.Password,
		Role:     coalesce(input.Role, "User"),
		Status:   coalesce(input.Status, "Waiting"),
	}, nil
}

func (store *userStore) Delete(ctx context.Context, id int64) error {
	result, err := store.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
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

func (store *userStore) userExists(ctx context.Context, id int64) (bool, error) {
	var exists int
	row := store.db.QueryRowContext(ctx, `SELECT 1 FROM users WHERE id = ?`, id)
	if err := row.Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (store *userStore) UpdateUserServers(ctx context.Context, userID int64, serverIDs []int64) error {
	uniqueIDs := uniqueInt64(serverIDs)

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM server_users WHERE user_id = ?`, userID); err != nil {
		_ = tx.Rollback()
		return err
	}

	for _, serverID := range uniqueIDs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO server_users (server_id, user_id)
			VALUES (?, ?)`,
			serverID,
			userID,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}

	return tx.Commit()
}

var errNotFound = errors.New("not found")

func IsNotFound(err error) bool {
	return errors.Is(err, errNotFound)
}

func IsDuplicateEmail(err error) bool {
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		return mysqlErr.Number == 1062
	}
	return false
}

func coalesce(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func nullableString(value string) sql.NullString {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

type serverRefs struct {
	ids   []int64
	names []string
}

func (store *userStore) userServers(ctx context.Context, userIDs []int64) (map[int64]serverRefs, error) {
	ids := uniqueInt64(userIDs)
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
		SELECT su.user_id, s.id, s.name
		FROM server_users su
		JOIN servers s ON s.id = su.server_id
		WHERE su.user_id IN (%s)
		ORDER BY s.name`, strings.Join(placeholders, ","))

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64]serverRefs{}
	for rows.Next() {
		var userID int64
		var serverID int64
		var name sql.NullString
		if err := rows.Scan(&userID, &serverID, &name); err != nil {
			return nil, err
		}
		entry := result[userID]
		entry.ids = append(entry.ids, serverID)
		if name.Valid && strings.TrimSpace(name.String) != "" {
			entry.names = append(entry.names, name.String)
		}
		result[userID] = entry
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
