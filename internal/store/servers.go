package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
	"strconv"
	"strings"
	"time"

	"vue-project-backend/internal/secretbox"
)

type Server struct {
	ID               int64
	Name             string
	IP               string
	Status           string
	ServiceStatus    string
	L4Status         string
	L7Status         string
	LicenseType      string
	LicenseFile      string
	Version          string
	OS               string
	SSHUser          string
	SSHPassword      string
	SSHPrivateKey    string
	SSHKeyPassphrase string
	SSHPort          string
	Token            string
	Created          sql.NullTime
	Expired          sql.NullTime
}

type ServerView struct {
	ID                  int64    `json:"id"`
	Name                string   `json:"name"`
	IP                  string   `json:"ip"`
	Status              string   `json:"status"`
	ServiceStatus       string   `json:"serviceStatus,omitempty"`
	L4Status            string   `json:"l4Status,omitempty"`
	L7Status            string   `json:"l7Status,omitempty"`
	ServiceStatusReason string   `json:"serviceStatusReason,omitempty"`
	L4StatusReason      string   `json:"l4StatusReason,omitempty"`
	L7StatusReason      string   `json:"l7StatusReason,omitempty"`
	StatusLabel         string   `json:"statusLabel"`
	StatusClass         string   `json:"statusClass"`
	License             string   `json:"license"`
	LicenseFile         string   `json:"licenseFile"`
	Version             string   `json:"version"`
	OS                  string   `json:"os,omitempty"`
	SSHUser             string   `json:"sshUser"`
	SSHPassword         string   `json:"-"`
	HasSSHPassword      bool     `json:"hasSshPassword"`
	SSHPrivateKey       string   `json:"-"`
	SSHKeyPassphrase    string   `json:"-"`
	HasSSHKey           bool     `json:"hasSshKey"`
	SSHAuthType         string   `json:"sshAuthType"`
	SSHPort             string   `json:"sshPort"`
	ExpiredDate         string   `json:"expiredDate"`
	Created             string   `json:"created"`
	Users               int      `json:"users"`
	ManagedUsers        []string `json:"managedUsers"`
	ManagedUserIds      []int64  `json:"managedUserIds"`
	Token               string   `json:"-"`
}

type ServerInput struct {
	Name          string
	IP            string
	Status        string
	ServiceStatus string
	L4Status      string
	L7Status      string
	LicenseType   string
	LicenseFile   string
	Version       string
	OS            string
	SSHUser       string
	SSHPassword   string
	SSHPort       string
	Token         string
	Expired       *time.Time
	// SSHPrivateKey / SSHKeyPassphrase: blank keeps the stored value on Update.
	SSHPrivateKey    string
	SSHKeyPassphrase string
	// ClearSSHKey removes the stored private key and passphrase on Update.
	ClearSSHKey bool
	// ClearSSHPassword removes the stored SSH password on Update.
	ClearSSHPassword bool
}

const (
	SSHAuthPassword = "password"
	SSHAuthKey      = "key"
)

// SSHAuthTypeOf reports how an edge authenticates: an edge with a private key uses it.
func SSHAuthTypeOf(privateKey string) string {
	if strings.TrimSpace(privateKey) != "" {
		return SSHAuthKey
	}
	return SSHAuthPassword
}

type ServerStore interface {
	ListWithUsers(ctx context.Context) ([]ServerView, error)
	Count(ctx context.Context) (int64, error)
	CountByStatus(ctx context.Context, status string) (int64, error)
	CountActiveRuntime(ctx context.Context) (int64, error)
	CountScoped(ctx context.Context, serverIDs []int64) (total int64, active int64, err error)
	UpdateServerUsers(ctx context.Context, serverID int64, userIDs []int64) error
	Create(ctx context.Context, input ServerInput) (Server, error)
	GetView(ctx context.Context, serverID int64) (ServerView, error)
	GetByToken(ctx context.Context, token string) (Server, error)
	UpdateDeploymentData(ctx context.Context, serverID int64, token, rowStatus, licenseType, version, os string, expired *time.Time, serviceStatus, l4Status, l7Status string) error
	Update(ctx context.Context, serverID int64, input ServerInput) error
	Delete(ctx context.Context, serverID int64) error
	EncryptLegacySecrets(ctx context.Context) (int, error)
}

type serverStore struct {
	db  *sql.DB
	box *secretbox.Box
}

func NewServerStore(db *sql.DB, box *secretbox.Box) ServerStore {
	return &serverStore{db: db, box: box}
}

func (store *serverStore) sealSSHPassword(value string) (sql.NullString, error) {
	return store.sealSecret(strings.TrimSpace(value))
}

func (store *serverStore) sealSecret(value string) (sql.NullString, error) {
	if value == "" {
		return sql.NullString{}, nil
	}
	sealed, err := store.box.Seal(value)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: sealed, Valid: true}, nil
}

func (store *serverStore) openSSHPassword(serverID int64, value sql.NullString) string {
	return store.openSecret(serverID, "ssh password", value)
}

// openSecret never fails the whole row load: a value that cannot be
// decrypted is logged and treated as missing so SSH reports an auth error.
func (store *serverStore) openSecret(serverID int64, label string, value sql.NullString) string {
	if !value.Valid || value.String == "" {
		return ""
	}
	plain, err := store.box.Open(value.String)
	if err != nil {
		log.Printf("[store] server %d: %s: %v", serverID, label, err)
		return ""
	}
	return plain
}

// EncryptLegacySecrets seals ssh_password values still stored in plaintext.
func (store *serverStore) EncryptLegacySecrets(ctx context.Context) (int, error) {
	return sealLegacyColumn(ctx, store.db, store.box, "servers", "ssh_password")
}

type userRef struct {
	ID   int64
	Name string
}

func (store *serverStore) ListWithUsers(ctx context.Context) ([]ServerView, error) {
	servers, err := store.listServers(ctx)
	if err != nil {
		return nil, err
	}

	userMap, err := store.serverUsers(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ServerView, 0, len(servers))
	for _, server := range servers {
		users := userMap[server.ID]
		names := make([]string, 0, len(users))
		ids := make([]int64, 0, len(users))
		for _, user := range users {
			names = append(names, user.Name)
			ids = append(ids, user.ID)
		}
		sort.Strings(names)

		pillSource := serverPillDisplayStatus(server)
		statusLabel, statusClass := normalizeStatus(pillSource)

		views = append(views, ServerView{
			ID:             server.ID,
			Name:           server.Name,
			IP:             server.IP,
			Status:         server.Status,
			ServiceStatus:  server.ServiceStatus,
			L4Status:       server.L4Status,
			L7Status:       server.L7Status,
			StatusLabel:    statusLabel,
			StatusClass:    statusClass,
			License:        server.LicenseType,
			LicenseFile:    server.LicenseFile,
			Version:        server.Version,
			OS:             server.OS,
			SSHUser:        server.SSHUser,
			HasSSHPassword: server.SSHPassword != "",
			HasSSHKey:      server.SSHPrivateKey != "",
			SSHAuthType:    SSHAuthTypeOf(server.SSHPrivateKey),
			SSHPort:        server.SSHPort,
			ExpiredDate:    formatDate(server.Expired),
			Created:        formatDate(server.Created),
			Users:          len(users),
			ManagedUsers:   names,
			ManagedUserIds: ids,
		})
	}

	return views, nil
}

func (store *serverStore) Count(ctx context.Context) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers`)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

func (store *serverStore) CountByStatus(ctx context.Context, status string) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE status = ?`, strings.TrimSpace(status))
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// CountActiveRuntime counts edges whose orchestrator runtime is up (service_status),
// falling back to row status Normal when runtime has not been probed yet.
func (store *serverStore) CountActiveRuntime(ctx context.Context) (int64, error) {
	var total int64
	row := store.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM servers
		WHERE LOWER(TRIM(COALESCE(service_status, ''))) IN ('running', 'active', 'enable')
		   OR (
		     TRIM(COALESCE(service_status, '')) = ''
		     AND status = 'Normal'
		   )`)
	if err := row.Scan(&total); err != nil {
		return 0, err
	}
	return total, nil
}

// CountScoped returns total and runtime-active edges among serverIDs.
func (store *serverStore) CountScoped(ctx context.Context, serverIDs []int64) (int64, int64, error) {
	query, args := appendIDAllowList(`
		SELECT COUNT(*),
			COALESCE(SUM(CASE
				WHEN LOWER(TRIM(COALESCE(service_status, ''))) IN ('running', 'active', 'enable') THEN 1
				WHEN TRIM(COALESCE(service_status, '')) = '' AND status = 'Normal' THEN 1
				ELSE 0 END), 0)
		FROM servers
		WHERE 1 = 1`, nil, "id", serverIDs)
	var total, active int64
	if err := store.db.QueryRowContext(ctx, query, args...).Scan(&total, &active); err != nil {
		return 0, 0, err
	}
	return total, active, nil
}

func (store *serverStore) Create(ctx context.Context, input ServerInput) (Server, error) {
	now := time.Now()
	status := strings.TrimSpace(input.Status)
	if status == "" {
		status = "Normal"
	}
	licenseType := strings.TrimSpace(input.LicenseType)
	if licenseType == "" {
		licenseType = "Trial"
	}
	serviceStatus := strings.TrimSpace(input.ServiceStatus)
	l4Status := strings.TrimSpace(input.L4Status)
	l7Status := strings.TrimSpace(input.L7Status)
	versionTrim := strings.TrimSpace(input.Version)
	var versionInsert any
	if versionTrim != "" {
		versionInsert = versionTrim
	}
	osTrim := strings.TrimSpace(input.OS)
	var osInsert any
	if osTrim != "" {
		osInsert = osTrim
	}

	var expired sql.NullTime
	if input.Expired != nil {
		expired = sql.NullTime{Time: *input.Expired, Valid: true}
	}
	sshPassword, err := store.sealSSHPassword(input.SSHPassword)
	if err != nil {
		return Server{}, err
	}
	sshKey, err := store.sealSecret(strings.TrimSpace(input.SSHPrivateKey))
	if err != nil {
		return Server{}, err
	}
	sshKeyPassphrase, err := store.sealSecret(input.SSHKeyPassphrase)
	if err != nil {
		return Server{}, err
	}

	result, err := store.db.ExecContext(ctx, `
		INSERT INTO servers (name, ip, status, service_status, l4_status, l7_status, license_type, license_file, version, os, ssh_user, ssh_password, ssh_private_key, ssh_key_passphrase, ssh_port, token, created, expired)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nullableServerString(input.Name),
		nullableServerString(input.IP),
		status,
		nullableServerString(serviceStatus),
		nullableServerString(l4Status),
		nullableServerString(l7Status),
		licenseType,
		nullableServerString(input.LicenseFile),
		versionInsert,
		osInsert,
		nullableServerString(input.SSHUser),
		sshPassword,
		sshKey,
		sshKeyPassphrase,
		nullableServerInt(input.SSHPort),
		nullableServerString(input.Token),
		now,
		expired,
	)
	if err != nil {
		return Server{}, err
	}

	id, err := result.LastInsertId()
	if err != nil {
		return Server{}, err
	}

	return Server{
		ID:               id,
		Name:             input.Name,
		IP:               input.IP,
		Status:           status,
		ServiceStatus:    serviceStatus,
		L4Status:         l4Status,
		L7Status:         l7Status,
		LicenseType:      licenseType,
		LicenseFile:      input.LicenseFile,
		Version:          versionTrim,
		OS:               osTrim,
		SSHUser:          input.SSHUser,
		SSHPassword:      input.SSHPassword,
		SSHPrivateKey:    strings.TrimSpace(input.SSHPrivateKey),
		SSHKeyPassphrase: input.SSHKeyPassphrase,
		SSHPort:          input.SSHPort,
		Token:            input.Token,
		Created:          sql.NullTime{Time: now, Valid: true},
		Expired:          expired,
	}, nil
}

func (store *serverStore) UpdateDeploymentData(ctx context.Context, serverID int64, token, rowStatus, licenseType, version, os string, expired *time.Time, serviceStatus, l4Status, l7Status string) error {
	var expiredValue sql.NullTime
	if expired != nil {
		expiredValue = sql.NullTime{Time: *expired, Valid: true}
	}

	_, err := store.db.ExecContext(ctx, `
		UPDATE servers
		SET token = ?,
			status = COALESCE(NULLIF(?, ''), status),
			service_status = COALESCE(NULLIF(?, ''), service_status),
			l4_status = COALESCE(NULLIF(?, ''), l4_status),
			l7_status = COALESCE(NULLIF(?, ''), l7_status),
			license_type = COALESCE(NULLIF(?, ''), license_type),
			version = COALESCE(NULLIF(?, ''), version),
			os = COALESCE(NULLIF(?, ''), os),
			expired = COALESCE(?, expired)
		WHERE id = ?`,
		nullableServerString(token),
		strings.TrimSpace(rowStatus),
		strings.TrimSpace(serviceStatus),
		strings.TrimSpace(l4Status),
		strings.TrimSpace(l7Status),
		strings.TrimSpace(licenseType),
		strings.TrimSpace(version),
		strings.TrimSpace(os),
		expiredValue,
		serverID,
	)
	return err
}

func (store *serverStore) Update(ctx context.Context, serverID int64, input ServerInput) error {
	status := strings.TrimSpace(input.Status)
	licenseType := strings.TrimSpace(input.LicenseType)
	sshPassword, err := store.sealSSHPassword(input.SSHPassword)
	if err != nil {
		return err
	}
	sshKey, err := store.sealSecret(strings.TrimSpace(input.SSHPrivateKey))
	if err != nil {
		return err
	}
	sshKeyPassphrase, err := store.sealSecret(input.SSHKeyPassphrase)
	if err != nil {
		return err
	}
	keyExpr, passphraseExpr := "COALESCE(?, ssh_private_key)", "COALESCE(?, ssh_key_passphrase)"
	if input.ClearSSHKey {
		keyExpr, passphraseExpr = "?", "?"
		sshKey, sshKeyPassphrase = sql.NullString{}, sql.NullString{}
	} else if sshKey.Valid {
		// A new key replaces the old passphrase too (blank = unencrypted key).
		passphraseExpr = "?"
	}
	passwordExpr := "COALESCE(?, ssh_password)"
	if input.ClearSSHPassword {
		passwordExpr = "?"
		sshPassword = sql.NullString{}
	}

	// Blank fields keep the stored value: the edit form does not send license or
	// version data, and the API never returns the SSH password to clients.
	_, err = store.db.ExecContext(ctx, `
		UPDATE servers
		SET name = ?, ip = ?, status = COALESCE(?, status), license_type = COALESCE(?, license_type),
			license_file = COALESCE(?, license_file), version = COALESCE(?, version),
			ssh_user = ?, ssh_password = `+passwordExpr+`,
			ssh_private_key = `+keyExpr+`, ssh_key_passphrase = `+passphraseExpr+`, ssh_port = ?
		WHERE id = ?`,
		nullableServerString(input.Name),
		nullableServerString(input.IP),
		nullableServerString(status),
		nullableServerString(licenseType),
		nullableServerString(input.LicenseFile),
		nullableServerString(input.Version),
		nullableServerString(input.SSHUser),
		sshPassword,
		sshKey,
		sshKeyPassphrase,
		nullableServerInt(input.SSHPort),
		serverID,
	)
	return err
}

func (store *serverStore) Delete(ctx context.Context, serverID int64) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM servers WHERE id = ?`, serverID)
	return err
}

func (store *serverStore) GetView(ctx context.Context, serverID int64) (ServerView, error) {
	server, err := store.getServer(ctx, serverID)
	if err != nil {
		return ServerView{}, err
	}

	users, err := store.serverUsersForServer(ctx, serverID)
	if err != nil {
		return ServerView{}, err
	}

	names := make([]string, 0, len(users))
	ids := make([]int64, 0, len(users))
	for _, user := range users {
		names = append(names, user.Name)
		ids = append(ids, user.ID)
	}
	sort.Strings(names)

	pillSource := serverPillDisplayStatus(server)
	statusLabel, statusClass := normalizeStatus(pillSource)

	return ServerView{
		ID:               server.ID,
		Name:             server.Name,
		IP:               server.IP,
		Status:           server.Status,
		ServiceStatus:    server.ServiceStatus,
		L4Status:         server.L4Status,
		L7Status:         server.L7Status,
		StatusLabel:      statusLabel,
		StatusClass:      statusClass,
		License:          server.LicenseType,
		LicenseFile:      server.LicenseFile,
		Version:          server.Version,
		OS:               server.OS,
		SSHUser:          server.SSHUser,
		SSHPassword:      server.SSHPassword,
		HasSSHPassword:   server.SSHPassword != "",
		SSHPrivateKey:    server.SSHPrivateKey,
		SSHKeyPassphrase: server.SSHKeyPassphrase,
		HasSSHKey:        server.SSHPrivateKey != "",
		SSHAuthType:      SSHAuthTypeOf(server.SSHPrivateKey),
		SSHPort:          server.SSHPort,
		ExpiredDate:      formatDate(server.Expired),
		Created:          formatDate(server.Created),
		Users:            len(users),
		ManagedUsers:     names,
		ManagedUserIds:   ids,
		Token:            server.Token,
	}, nil
}

func (store *serverStore) UpdateServerUsers(ctx context.Context, serverID int64, userIDs []int64) error {
	uniqueIDs := uniqueInt64(userIDs)
	filteredIDs, err := store.filterUserRoleIDs(ctx, uniqueIDs, "User", "Admin")
	if err != nil {
		return err
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM server_users WHERE server_id = ?`, serverID); err != nil {
		_ = tx.Rollback()
		return err
	}

	for _, userID := range filteredIDs {
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

func (store *serverStore) listServers(ctx context.Context) ([]Server, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT id, name, ip, status, service_status, l4_status, l7_status, license_type, license_file, version, os, ssh_user, ssh_password, ssh_private_key, ssh_key_passphrase, ssh_port, token, created, expired
		FROM servers
		ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []Server
	for rows.Next() {
		var item Server
		var name sql.NullString
		var ip sql.NullString
		var status sql.NullString
		var serviceStatus sql.NullString
		var l4Status sql.NullString
		var l7Status sql.NullString
		var licenseType sql.NullString
		var licenseFile sql.NullString
		var version sql.NullString
		var osLabel sql.NullString
		var sshUser sql.NullString
		var sshPassword sql.NullString
		var sshKey sql.NullString
		var sshKeyPassphrase sql.NullString
		var sshPort sql.NullInt64
		var token sql.NullString
		if err := rows.Scan(
			&item.ID,
			&name,
			&ip,
			&status,
			&serviceStatus,
			&l4Status,
			&l7Status,
			&licenseType,
			&licenseFile,
			&version,
			&osLabel,
			&sshUser,
			&sshPassword,
			&sshKey,
			&sshKeyPassphrase,
			&sshPort,
			&token,
			&item.Created,
			&item.Expired,
		); err != nil {
			return nil, err
		}
		item.Name = nullStringValue(name)
		item.IP = nullStringValue(ip)
		item.Status = nullStringValue(status)
		item.ServiceStatus = nullStringValue(serviceStatus)
		item.L4Status = nullStringValue(l4Status)
		item.L7Status = nullStringValue(l7Status)
		item.LicenseType = nullStringValue(licenseType)
		item.LicenseFile = nullStringValue(licenseFile)
		item.Version = nullStringValue(version)
		item.OS = nullStringValue(osLabel)
		item.SSHUser = nullStringValue(sshUser)
		item.SSHPassword = nullStringValue(sshPassword)
		item.SSHPrivateKey = nullStringValue(sshKey)
		item.SSHPort = nullIntStringValue(sshPort)
		item.Token = nullStringValue(token)
		servers = append(servers, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return servers, nil
}

func (store *serverStore) getServer(ctx context.Context, serverID int64) (Server, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT id, name, ip, status, service_status, l4_status, l7_status, license_type, license_file, version, os, ssh_user, ssh_password, ssh_private_key, ssh_key_passphrase, ssh_port, token, created, expired
		FROM servers
		WHERE id = ?`, serverID)

	var item Server
	var name sql.NullString
	var ip sql.NullString
	var status sql.NullString
	var serviceStatus sql.NullString
	var l4Status sql.NullString
	var l7Status sql.NullString
	var licenseType sql.NullString
	var licenseFile sql.NullString
	var version sql.NullString
	var osLabel sql.NullString
	var sshUser sql.NullString
	var sshPassword sql.NullString
	var sshKey sql.NullString
	var sshKeyPassphrase sql.NullString
	var sshPort sql.NullInt64
	var token sql.NullString
	if err := row.Scan(
		&item.ID,
		&name,
		&ip,
		&status,
		&serviceStatus,
		&l4Status,
		&l7Status,
		&licenseType,
		&licenseFile,
		&version,
		&osLabel,
		&sshUser,
		&sshPassword,
		&sshKey,
		&sshKeyPassphrase,
		&sshPort,
		&token,
		&item.Created,
		&item.Expired,
	); err != nil {
		return Server{}, err
	}

	item.Name = nullStringValue(name)
	item.IP = nullStringValue(ip)
	item.Status = nullStringValue(status)
	item.ServiceStatus = nullStringValue(serviceStatus)
	item.L4Status = nullStringValue(l4Status)
	item.L7Status = nullStringValue(l7Status)
	item.LicenseType = nullStringValue(licenseType)
	item.LicenseFile = nullStringValue(licenseFile)
	item.Version = nullStringValue(version)
	item.OS = nullStringValue(osLabel)
	item.SSHUser = nullStringValue(sshUser)
	item.SSHPassword = store.openSSHPassword(item.ID, sshPassword)
	item.SSHPrivateKey = store.openSecret(item.ID, "ssh private key", sshKey)
	item.SSHKeyPassphrase = store.openSecret(item.ID, "ssh key passphrase", sshKeyPassphrase)
	item.SSHPort = nullIntStringValue(sshPort)
	item.Token = nullStringValue(token)
	return item, nil
}

func (store *serverStore) GetByToken(ctx context.Context, token string) (Server, error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT id, name, ip, status, service_status, l4_status, l7_status, license_type, license_file, version, ssh_user, ssh_password, ssh_private_key, ssh_key_passphrase, ssh_port, token, created, expired
		FROM servers
		WHERE token = ?`, token)

	var item Server
	var name sql.NullString
	var ip sql.NullString
	var status sql.NullString
	var serviceStatus sql.NullString
	var l4Status sql.NullString
	var l7Status sql.NullString
	var licenseType sql.NullString
	var licenseFile sql.NullString
	var version sql.NullString
	var sshUser sql.NullString
	var sshPassword sql.NullString
	var sshKey sql.NullString
	var sshKeyPassphrase sql.NullString
	var sshPort sql.NullInt64
	var tokenValue sql.NullString
	if err := row.Scan(
		&item.ID,
		&name,
		&ip,
		&status,
		&serviceStatus,
		&l4Status,
		&l7Status,
		&licenseType,
		&licenseFile,
		&version,
		&sshUser,
		&sshPassword,
		&sshKey,
		&sshKeyPassphrase,
		&sshPort,
		&tokenValue,
		&item.Created,
		&item.Expired,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Server{}, errNotFound
		}
		return Server{}, err
	}

	item.Name = nullStringValue(name)
	item.IP = nullStringValue(ip)
	item.Status = nullStringValue(status)
	item.ServiceStatus = nullStringValue(serviceStatus)
	item.L4Status = nullStringValue(l4Status)
	item.L7Status = nullStringValue(l7Status)
	item.LicenseType = nullStringValue(licenseType)
	item.LicenseFile = nullStringValue(licenseFile)
	item.Version = nullStringValue(version)
	item.SSHUser = nullStringValue(sshUser)
	item.SSHPassword = store.openSSHPassword(item.ID, sshPassword)
	item.SSHPrivateKey = store.openSecret(item.ID, "ssh private key", sshKey)
	item.SSHKeyPassphrase = store.openSecret(item.ID, "ssh key passphrase", sshKeyPassphrase)
	item.SSHPort = nullIntStringValue(sshPort)
	item.Token = nullStringValue(tokenValue)
	return item, nil
}

func nullStringValue(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func (store *serverStore) serverUsers(ctx context.Context) (map[int64][]userRef, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT su.server_id, u.id, u.name
		FROM server_users su
		JOIN users u ON u.id = su.user_id
		ORDER BY u.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := map[int64][]userRef{}
	for rows.Next() {
		var serverID int64
		var userID int64
		var name string
		if err := rows.Scan(&serverID, &userID, &name); err != nil {
			return nil, err
		}
		result[serverID] = append(result[serverID], userRef{ID: userID, Name: name})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (store *serverStore) serverUsersForServer(ctx context.Context, serverID int64) ([]userRef, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT u.id, u.name
		FROM server_users su
		JOIN users u ON u.id = su.user_id
		WHERE su.server_id = ?
		ORDER BY u.name`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []userRef
	for rows.Next() {
		var user userRef
		if err := rows.Scan(&user.ID, &user.Name); err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}

func formatDate(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.Format("Jan 02, 2006")
}

func formatTimestamp(value sql.NullTime) string {
	if !value.Valid {
		return ""
	}
	return value.Time.UTC().Format(time.RFC3339)
}

// serverPillDisplayStatus prefers deploy/runtime service_status when set; otherwise the row status ENUM.
func serverPillDisplayStatus(s Server) string {
	if v := strings.TrimSpace(s.ServiceStatus); v != "" {
		return v
	}
	return strings.TrimSpace(s.Status)
}

func normalizeStatus(status string) (string, string) {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "normal":
		return "Normal", "active"
	case "pause":
		return "Pause", "inactive"
	case "expired":
		return "Expired", "maintenance"
	case "running":
		return "Running", "running"
	case "deployed":
		return "Deployed", "deployed"
	case "stopped":
		return "Stopped", "stopped"
	case "unknown":
		return "Unknown", "unknown"
	default:
		return status, "inactive"
	}
}

func nullableServerString(value string) sql.NullString {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: trimmed, Valid: true}
}

func nullableServerInt(value string) sql.NullInt64 {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return sql.NullInt64{Valid: false}
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return sql.NullInt64{Valid: false}
	}
	return sql.NullInt64{Int64: parsed, Valid: true}
}

func nullIntStringValue(value sql.NullInt64) string {
	if !value.Valid {
		return ""
	}
	return strconv.FormatInt(value.Int64, 10)
}

func uniqueInt64(values []int64) []int64 {
	if len(values) == 0 {
		return nil
	}
	seen := map[int64]struct{}{}
	result := make([]int64, 0, len(values))
	for _, value := range values {
		if value == 0 {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func (store *serverStore) filterUserRoleIDs(ctx context.Context, ids []int64, roles ...string) ([]int64, error) {
	if len(ids) == 0 || len(roles) == 0 {
		return nil, nil
	}

	placeholders := make([]string, 0, len(ids))
	args := make([]any, 0, len(ids)+len(roles))
	for _, id := range ids {
		placeholders = append(placeholders, "?")
		args = append(args, id)
	}
	rolePlaceholders := make([]string, 0, len(roles))
	for _, role := range roles {
		rolePlaceholders = append(rolePlaceholders, "?")
		args = append(args, role)
	}

	query := fmt.Sprintf(
		`SELECT id FROM users WHERE id IN (%s) AND role IN (%s)`,
		strings.Join(placeholders, ","),
		strings.Join(rolePlaceholders, ","),
	)

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var filtered []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		filtered = append(filtered, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return filtered, nil
}
