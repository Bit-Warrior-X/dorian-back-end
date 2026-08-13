package store

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisKeyBlacklistNext  = "temporaryblacklist_backend:id"
	redisKeyBlacklistEntry = "temporaryblacklist_backend:entry:" // entry key: temporaryblacklist:entry:{id}; EXPIRE set so Redis deletes when TTL elapses
	// defaultExpireSeconds is used when ttl is 0 so the key still expires eventually
	defaultExpireSeconds = 180 // 3 minutes
)

type TemporaryBlacklistPayload struct {
	Token       string `json:"token,omitempty"`
	IP          string `json:"ip"`
	URL         string `json:"url"`
	Country     string `json:"country"`
	City        string `json:"city"`
	BlockedAt   string `json:"blocked_at"`
	TTL         int64  `json:"ttl"`
	TriggerRule string `json:"trigger_rule"`
	ServerID    int64  `json:"server_id,omitempty"`
	SiteID      int64  `json:"site_id,omitempty"`
	Server      string `json:"server,omitempty"`
}

func (p *TemporaryBlacklistPayload) UnmarshalJSON(data []byte) error {
	type raw TemporaryBlacklistPayload
	var decoded raw
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*p = TemporaryBlacklistPayload(decoded)
	if p.SiteID != 0 {
		return nil
	}
	var extra struct {
		SiteIDCamel int64 `json:"siteId"`
	}
	if err := json.Unmarshal(data, &extra); err != nil {
		return err
	}
	p.SiteID = extra.SiteIDCamel
	return nil
}

type BlacklistEntry struct {
	ID          int64  `json:"id"`
	ServerID    int64  `json:"serverId"`
	SiteID      int64  `json:"siteId,omitempty"`
	IPAddress   string `json:"ipAddress"`
	Geolocation string `json:"geolocation"`
	Reason      string `json:"reason"`
	URL         string `json:"url"`
	Server      string `json:"server"`
	TTL         string `json:"ttl"`
	TriggerRule string `json:"triggerRule"`
	CreatedAt   string `json:"createdAt"`
	ExpireAt    string `json:"expireAt"`
	UpdatedAt   string `json:"updatedAt"`
}

type BlacklistInput struct {
	IPAddress   string
	Geolocation string
	Reason      string
	URL         string
	Server      string
	TTL         string
	TriggerRule string
	SiteID      int64
}

type BlacklistStore interface {
	List(ctx context.Context, serverID, siteID int64) ([]BlacklistEntry, error)
	Count(ctx context.Context) (int64, error)
	Create(ctx context.Context, serverID int64, input BlacklistInput) (BlacklistEntry, error)
	CreateFromPayload(ctx context.Context, p TemporaryBlacklistPayload) (BlacklistEntry, error)
	// ListPayloadsByServer returns the raw temporary blacklist payloads for the
	// given server. If serverID is 0, entries for all servers are returned.
	ListPayloadsByServer(ctx context.Context, serverID int64) ([]TemporaryBlacklistPayload, error)
	// GetPayload returns the raw temporary blacklist payload for the given
	// entry id.
	GetPayload(ctx context.Context, entryID int64) (TemporaryBlacklistPayload, error)
	Delete(ctx context.Context, entryID int64) error
	DeleteAll(ctx context.Context, serverID int64) error
}

type blacklistStore struct {
	rdb *redis.Client
}

func NewBlacklistStore(rdb *redis.Client) BlacklistStore {
	return &blacklistStore{rdb: rdb}
}

func (s *blacklistStore) List(ctx context.Context, serverID, siteID int64) ([]BlacklistEntry, error) {
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return nil, err
	}
	var entries []BlacklistEntry
	for _, key := range keys {
		raw, err := s.rdb.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				continue // key expired and was removed
			}
			return nil, err
		}
		idStr := strings.TrimPrefix(key, redisKeyBlacklistEntry)
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			continue
		}
		var p TemporaryBlacklistPayload
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			continue
		}
		if serverID != 0 && p.ServerID != serverID {
			continue
		}
		if siteID != 0 && p.SiteID != siteID {
			continue
		}
		entries = append(entries, payloadToEntry(id, p))
	}
	// Sort by ID descending to match previous MySQL ORDER BY id DESC
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
	return entries, nil
}

// entryKeys returns all keys matching temporaryblacklist:entry:* using SCAN.
func (s *blacklistStore) entryKeys(ctx context.Context) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		var batch []string
		var err error
		batch, cursor, err = s.rdb.Scan(ctx, cursor, redisKeyBlacklistEntry+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

func (s *blacklistStore) Count(ctx context.Context) (int64, error) {
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return 0, err
	}
	return int64(len(keys)), nil
}

func (s *blacklistStore) Create(ctx context.Context, serverID int64, input BlacklistInput) (BlacklistEntry, error) {
	now := time.Now().UTC().Unix()
	p := TemporaryBlacklistPayload{
		IP:          strings.TrimSpace(input.IPAddress),
		URL:         strings.TrimSpace(input.URL),
		Country:     "",
		City:        strings.TrimSpace(input.Geolocation),
		BlockedAt:   strconv.FormatInt(now, 10),
		TTL:         0,
		TriggerRule: strings.TrimSpace(input.TriggerRule),
		ServerID:    serverID,
		SiteID:      input.SiteID,
		Server:      strings.TrimSpace(input.Server),
	}
	if ttl, _ := strconv.ParseInt(strings.TrimSpace(input.TTL), 10, 64); ttl > 0 {
		p.TTL = ttl
	}
	return s.CreateFromPayload(ctx, p)
}

func (s *blacklistStore) CreateFromPayload(ctx context.Context, p TemporaryBlacklistPayload) (BlacklistEntry, error) {
	id, err := s.rdb.Incr(ctx, redisKeyBlacklistNext).Result()
	if err != nil {
		return BlacklistEntry{}, err
	}
	// Normalize payload
	p.IP = strings.TrimSpace(p.IP)
	p.URL = strings.TrimSpace(p.URL)
	p.Country = strings.TrimSpace(p.Country)
	p.City = strings.TrimSpace(p.City)
	p.BlockedAt = strings.TrimSpace(p.BlockedAt)
	if p.BlockedAt == "" {
		p.BlockedAt = strconv.FormatInt(time.Now().UTC().Unix(), 10)
	}
	p.TriggerRule = strings.TrimSpace(p.TriggerRule)
	raw, err := json.Marshal(p)
	if err != nil {
		return BlacklistEntry{}, err
	}
	entryKey := redisKeyBlacklistEntry + strconv.FormatInt(id, 10)
	expireSec := p.TTL
	if expireSec <= 0 {
		expireSec = defaultExpireSeconds
	}
	if err := s.rdb.Set(ctx, entryKey, raw, time.Duration(expireSec)*time.Second).Err(); err != nil {
		return BlacklistEntry{}, err
	}
	return payloadToEntry(id, p), nil
}

func (s *blacklistStore) Delete(ctx context.Context, entryID int64) error {
	entryKey := redisKeyBlacklistEntry + strconv.FormatInt(entryID, 10)
	n, err := s.rdb.Del(ctx, entryKey).Result()
	if err != nil {
		return err
	}
	if n == 0 {
		return errNotFound
	}
	return nil
}

func (s *blacklistStore) DeleteAll(ctx context.Context, serverID int64) error {
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) > 0 {
		if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}
	if err := s.rdb.Del(ctx, redisKeyBlacklistNext).Err(); err != nil {
		return err
	}
	return nil
}

// ListPayloadsByServer returns the raw temporary blacklist payloads stored in
// Redis, optionally filtered by serverID. If serverID is 0, payloads for all
// servers are returned.
func (s *blacklistStore) ListPayloadsByServer(ctx context.Context, serverID int64) ([]TemporaryBlacklistPayload, error) {
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return nil, err
	}
	var payloads []TemporaryBlacklistPayload
	for _, key := range keys {
		raw, err := s.rdb.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				// Key expired and was removed.
				continue
			}
			return nil, err
		}
		var p TemporaryBlacklistPayload
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			// Skip malformed entries instead of failing the whole operation.
			continue
		}
		if serverID != 0 && p.ServerID != serverID {
			continue
		}
		payloads = append(payloads, p)
	}
	return payloads, nil
}

// GetPayload returns the raw temporary blacklist payload for the given entryID.
func (s *blacklistStore) GetPayload(ctx context.Context, entryID int64) (TemporaryBlacklistPayload, error) {
	var p TemporaryBlacklistPayload
	if entryID <= 0 {
		return p, errNotFound
	}
	entryKey := redisKeyBlacklistEntry + strconv.FormatInt(entryID, 10)
	raw, err := s.rdb.Get(ctx, entryKey).Result()
	if err != nil {
		if err == redis.Nil {
			return p, errNotFound
		}
		return p, err
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, err
	}
	return p, nil
}

func payloadToEntry(id int64, p TemporaryBlacklistPayload) BlacklistEntry {
	ttlStr := ""
	if p.TTL > 0 {
		ttlStr = strconv.FormatInt(p.TTL, 10)
	}
	geolocation := strings.TrimSpace(p.Country)
	if p.City != "" {
		if geolocation != "" {
			geolocation += ", "
		}
		geolocation += strings.TrimSpace(p.City)
	}
	createdAt := formatUnixTimestamp(p.BlockedAt)
	return BlacklistEntry{
		ID:          id,
		ServerID:    p.ServerID,
		SiteID:      p.SiteID,
		IPAddress:   p.IP,
		Geolocation: geolocation,
		Reason:      "",
		URL:         p.URL,
		Server:      p.Server,
		TTL:         ttlStr,
		TriggerRule: p.TriggerRule,
		CreatedAt:   createdAt,
		ExpireAt:    "",
		UpdatedAt:   createdAt,
	}
}

func formatUnixTimestamp(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	sec, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return s
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
