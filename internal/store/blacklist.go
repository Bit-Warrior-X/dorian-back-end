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
	// Live L4 attack blocks shown on the temporary-block page. Kept apart from
	// the L7 temporary list so a flush does not push them to the L7 agent.
	redisKeyL4TempNext  = "l4temporaryblock:id"
	redisKeyL4TempEntry = "l4temporaryblock:entry:"
	// Per-edge SET of entry ids so ReplaceL4Temporary does not SCAN the whole keyspace.
	redisKeyL4TempServerIdx = "l4temporaryblock:serveridx:"
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
	Reason      string `json:"reason,omitempty"`
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
	ReplaceForServer(ctx context.Context, serverID int64, payloads []TemporaryBlacklistPayload) error
	// ReplaceL4Temporary replaces the current live L4 blocks for one edge.
	ReplaceL4Temporary(ctx context.Context, serverID int64, payloads []TemporaryBlacklistPayload) error
	ListL4Temporary(ctx context.Context, serverID int64) ([]BlacklistEntry, error)
	// GetL4Temporary returns the live L4 block for an entry id.
	GetL4Temporary(ctx context.Context, entryID int64) (TemporaryBlacklistPayload, error)
	DeleteL4Temporary(ctx context.Context, entryID int64) error
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
		if _, active := blockLifetime(p, time.Now().UTC()); !active {
			_ = s.rdb.Del(ctx, key)
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
	// Normalize payload
	p.IP = strings.TrimSpace(p.IP)
	p.URL = strings.TrimSpace(p.URL)
	p.Country = strings.TrimSpace(p.Country)
	p.City = strings.TrimSpace(p.City)
	p.BlockedAt = strings.TrimSpace(p.BlockedAt)
	now := time.Now().UTC()
	if p.BlockedAt == "" {
		p.BlockedAt = strconv.FormatInt(now.Unix(), 10)
	}
	p.TriggerRule = strings.TrimSpace(p.TriggerRule)
	p.Reason = strings.TrimSpace(p.Reason)
	remaining, active := blockLifetime(p, now)
	if !active {
		// Edge still reported this block (one-shot notify or configure snapshot),
		// but blocked_at+ttl is already past — common on re-notifies with the
		// original blocked_at and a short TTL. Keep it visible from now.
		if p.TTL <= 0 {
			p.TTL = int64(defaultExpireSeconds)
		}
		p.BlockedAt = strconv.FormatInt(now.Unix(), 10)
		remaining = time.Duration(p.TTL) * time.Second
	}

	// Refresh an existing live row for the same IP/site/URL instead of creating
	// duplicates when Angelos re-notifies or configure sync overlaps.
	idKey := tempIdentity(p)
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return BlacklistEntry{}, err
	}
	for _, key := range keys {
		rawExisting, getErr := s.rdb.Get(ctx, key).Bytes()
		if getErr != nil {
			if getErr == redis.Nil {
				continue
			}
			return BlacklistEntry{}, getErr
		}
		var existing TemporaryBlacklistPayload
		if err := json.Unmarshal(rawExisting, &existing); err != nil {
			continue
		}
		if existing.ServerID != p.ServerID {
			continue
		}
		if tempIdentity(existing) != idKey {
			continue
		}
		idStr := strings.TrimPrefix(key, redisKeyBlacklistEntry)
		id, parseErr := strconv.ParseInt(idStr, 10, 64)
		if parseErr != nil {
			continue
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return BlacklistEntry{}, err
		}
		if err := s.rdb.Set(ctx, key, raw, remaining).Err(); err != nil {
			return BlacklistEntry{}, err
		}
		return payloadToEntry(id, p), nil
	}

	id, err := s.rdb.Incr(ctx, redisKeyBlacklistNext).Result()
	if err != nil {
		return BlacklistEntry{}, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return BlacklistEntry{}, err
	}
	entryKey := redisKeyBlacklistEntry + strconv.FormatInt(id, 10)
	if err := s.rdb.Set(ctx, entryKey, raw, remaining).Err(); err != nil {
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
	if serverID == 0 {
		if len(keys) > 0 {
			if err := s.rdb.Del(ctx, keys...).Err(); err != nil {
				return err
			}
		}
		return s.rdb.Del(ctx, redisKeyBlacklistNext).Err()
	}

	var toDelete []string
	for _, key := range keys {
		raw, err := s.rdb.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return err
		}
		var p TemporaryBlacklistPayload
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			continue
		}
		if p.ServerID == serverID {
			toDelete = append(toDelete, key)
		}
	}
	if len(toDelete) == 0 {
		return nil
	}
	return s.rdb.Del(ctx, toDelete...).Err()
}

// tempIdentity dedupes one live L7 block (same IP+site+URL).
func tempIdentity(p TemporaryBlacklistPayload) string {
	return strings.ToLower(strings.TrimSpace(p.IP)) + "|" +
		strconv.FormatInt(p.SiteID, 10) + "|" +
		strings.TrimSpace(p.URL)
}

// replaceGrace is how long a one-shot temporary_blacklist_added entry is kept
// even if the next report_edge_configure snapshot omits it (Angelos often sends
// tempBL=0 for up to a minute after notifying).
const replaceGrace = 2 * time.Minute

func (s *blacklistStore) ReplaceForServer(ctx context.Context, serverID int64, payloads []TemporaryBlacklistPayload) error {
	if serverID == 0 {
		return errNotFound
	}

	type existing struct {
		key string
		p   TemporaryBlacklistPayload
	}
	keys, err := s.entryKeys(ctx)
	if err != nil {
		return err
	}
	byIdentity := make(map[string]existing)
	now := time.Now().UTC()
	for _, key := range keys {
		raw, err := s.rdb.Get(ctx, key).Bytes()
		if err != nil {
			if err == redis.Nil {
				continue
			}
			return err
		}
		var p TemporaryBlacklistPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			continue
		}
		if p.ServerID != serverID {
			continue
		}
		if _, active := blockLifetime(p, now); !active {
			_ = s.rdb.Del(ctx, key)
			continue
		}
		byIdentity[tempIdentity(p)] = existing{key: key, p: p}
	}

	// Empty edge snapshot must not wipe one-shot adds. Redis TTL still expires
	// each entry when its block ends.
	if len(payloads) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(payloads))
	for _, payload := range payloads {
		ip := strings.TrimSpace(payload.IP)
		if ip == "" {
			continue
		}
		payload.ServerID = serverID
		payload.IP = ip
		idKey := tempIdentity(payload)
		if _, ok := seen[idKey]; ok {
			continue
		}
		seen[idKey] = struct{}{}

		if prev, ok := byIdentity[idKey]; ok {
			remaining, active := blockLifetime(payload, now)
			if !active {
				if payload.TTL <= 0 {
					payload.TTL = int64(defaultExpireSeconds)
				}
				payload.BlockedAt = strconv.FormatInt(now.Unix(), 10)
				remaining = time.Duration(payload.TTL) * time.Second
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if err := s.rdb.Set(ctx, prev.key, raw, remaining).Err(); err != nil {
				return err
			}
			byIdentity[idKey] = existing{key: prev.key, p: payload}
			continue
		}
		if _, err := s.CreateFromPayload(ctx, payload); err != nil {
			return err
		}
	}

	// Drop entries missing from the snapshot only after the grace window so a
	// temporary_blacklist_added race with report_edge_configure cannot erase them.
	for idKey, item := range byIdentity {
		if _, ok := seen[idKey]; ok {
			continue
		}
		started, ok := parseBlockTime(item.p.BlockedAt)
		if ok && now.Sub(started) < replaceGrace {
			continue
		}
		_ = s.rdb.Del(ctx, item.key)
	}
	return nil
}

func (s *blacklistStore) l4TempKeys(ctx context.Context) ([]string, error) {
	var keys []string
	var cursor uint64
	for {
		batch, next, err := s.rdb.Scan(ctx, cursor, redisKeyL4TempEntry+"*", 100).Result()
		if err != nil {
			return nil, err
		}
		keys = append(keys, batch...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return keys, nil
}

func (s *blacklistStore) l4TempIndexKey(serverID int64) string {
	return redisKeyL4TempServerIdx + strconv.FormatInt(serverID, 10)
}

// l4TempKeysForServer returns entry keys for one edge via the server index,
// falling back to a one-shot SCAN for legacy data written before the index existed.
func (s *blacklistStore) l4TempKeysForServer(ctx context.Context, serverID int64) ([]string, error) {
	idxKey := s.l4TempIndexKey(serverID)
	ids, err := s.rdb.SMembers(ctx, idxKey).Result()
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		keys := make([]string, 0, len(ids))
		for _, id := range ids {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			keys = append(keys, redisKeyL4TempEntry+id)
		}
		return keys, nil
	}

	all, err := s.l4TempKeys(ctx)
	if err != nil {
		return nil, err
	}
	var matched []string
	const chunk = 200
	for i := 0; i < len(all); i += chunk {
		end := i + chunk
		if end > len(all) {
			end = len(all)
		}
		batch := all[i:end]
		values, err := s.rdb.MGet(ctx, batch...).Result()
		if err != nil {
			return nil, err
		}
		for j, value := range values {
			raw, ok := value.(string)
			if !ok || raw == "" {
				continue
			}
			var existing TemporaryBlacklistPayload
			if err := json.Unmarshal([]byte(raw), &existing); err != nil {
				matched = append(matched, batch[j])
				continue
			}
			if existing.ServerID == serverID {
				matched = append(matched, batch[j])
			}
		}
	}
	return matched, nil
}

func (s *blacklistStore) ReplaceL4Temporary(ctx context.Context, serverID int64, payloads []TemporaryBlacklistPayload) error {
	if serverID == 0 {
		return errNotFound
	}
	stale, err := s.l4TempKeysForServer(ctx, serverID)
	if err != nil {
		return err
	}
	idxKey := s.l4TempIndexKey(serverID)
	if len(stale) > 0 {
		toDelete := append(append([]string{}, stale...), idxKey)
		const delChunk = 500
		for i := 0; i < len(toDelete); i += delChunk {
			end := i + delChunk
			if end > len(toDelete) {
				end = len(toDelete)
			}
			if err := s.rdb.Del(ctx, toDelete[i:end]...).Err(); err != nil {
				return err
			}
		}
	} else {
		_ = s.rdb.Del(ctx, idxKey).Err()
	}

	type pending struct {
		raw       []byte
		remaining time.Duration
	}
	seen := make(map[string]struct{}, len(payloads))
	items := make([]pending, 0, len(payloads))
	now := time.Now().UTC()
	for _, payload := range payloads {
		ip := strings.TrimSpace(payload.IP)
		if ip == "" {
			continue
		}
		if _, ok := seen[strings.ToLower(ip)]; ok {
			continue
		}
		seen[strings.ToLower(ip)] = struct{}{}
		payload.ServerID = serverID
		payload.IP = ip
		payload.TriggerRule = "l4ddos"
		if _, active := blockLifetime(payload, now); !active {
			continue
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		remaining, _ := blockLifetime(payload, now)
		items = append(items, pending{raw: raw, remaining: remaining})
	}
	if len(items) == 0 {
		return nil
	}

	endID, err := s.rdb.IncrBy(ctx, redisKeyL4TempNext, int64(len(items))).Result()
	if err != nil {
		return err
	}
	startID := endID - int64(len(items)) + 1

	pipe := s.rdb.Pipeline()
	idStrs := make([]any, 0, len(items))
	for i, item := range items {
		id := startID + int64(i)
		idStr := strconv.FormatInt(id, 10)
		pipe.Set(ctx, redisKeyL4TempEntry+idStr, item.raw, item.remaining)
		idStrs = append(idStrs, idStr)
	}
	pipe.SAdd(ctx, idxKey, idStrs...)
	if _, err := pipe.Exec(ctx); err != nil {
		return err
	}
	return nil
}

func (s *blacklistStore) ListL4Temporary(ctx context.Context, serverID int64) ([]BlacklistEntry, error) {
	var keys []string
	var err error
	if serverID != 0 {
		keys, err = s.l4TempKeysForServer(ctx, serverID)
	} else {
		keys, err = s.l4TempKeys(ctx)
	}
	if err != nil {
		return nil, err
	}
	var entries []BlacklistEntry
	const chunk = 200
	now := time.Now().UTC()
	for i := 0; i < len(keys); i += chunk {
		end := i + chunk
		if end > len(keys) {
			end = len(keys)
		}
		batch := keys[i:end]
		values, err := s.rdb.MGet(ctx, batch...).Result()
		if err != nil {
			return nil, err
		}
		for j, value := range values {
			key := batch[j]
			raw, ok := value.(string)
			if !ok || raw == "" {
				if serverID != 0 {
					idStr := strings.TrimPrefix(key, redisKeyL4TempEntry)
					_ = s.rdb.SRem(ctx, s.l4TempIndexKey(serverID), idStr).Err()
				}
				continue
			}
			id, err := strconv.ParseInt(strings.TrimPrefix(key, redisKeyL4TempEntry), 10, 64)
			if err != nil {
				continue
			}
			var payload TemporaryBlacklistPayload
			if err := json.Unmarshal([]byte(raw), &payload); err != nil {
				continue
			}
			if serverID != 0 && payload.ServerID != serverID {
				continue
			}
			if _, active := blockLifetime(payload, now); !active {
				_ = s.rdb.Del(ctx, key).Err()
				if payload.ServerID != 0 {
					_ = s.rdb.SRem(ctx, s.l4TempIndexKey(payload.ServerID), strconv.FormatInt(id, 10)).Err()
				}
				continue
			}
			if strings.TrimSpace(payload.TriggerRule) == "" {
				payload.TriggerRule = "l4ddos"
			}
			entries = append(entries, payloadToEntry(id, payload))
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
	return entries, nil
}

func (s *blacklistStore) GetL4Temporary(ctx context.Context, entryID int64) (TemporaryBlacklistPayload, error) {
	var payload TemporaryBlacklistPayload
	if entryID <= 0 {
		return payload, errNotFound
	}
	raw, err := s.rdb.Get(ctx, redisKeyL4TempEntry+strconv.FormatInt(entryID, 10)).Result()
	if err != nil {
		if err == redis.Nil {
			return payload, errNotFound
		}
		return payload, err
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func (s *blacklistStore) DeleteL4Temporary(ctx context.Context, entryID int64) error {
	if entryID <= 0 {
		return nil
	}
	key := redisKeyL4TempEntry + strconv.FormatInt(entryID, 10)
	if payload, err := s.GetL4Temporary(ctx, entryID); err == nil && payload.ServerID != 0 {
		_ = s.rdb.SRem(ctx, s.l4TempIndexKey(payload.ServerID), strconv.FormatInt(entryID, 10)).Err()
	}
	return s.rdb.Del(ctx, key).Err()
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
		if _, active := blockLifetime(p, time.Now().UTC()); !active {
			_ = s.rdb.Del(ctx, key)
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
		Reason:      strings.TrimSpace(p.Reason),
		URL:         p.URL,
		Server:      p.Server,
		TTL:         ttlStr,
		TriggerRule: p.TriggerRule,
		CreatedAt:   createdAt,
		ExpireAt:    "",
		UpdatedAt:   createdAt,
	}
}

// blockLifetime is how long the block should remain stored and visible.
// A positive TTL is measured from blocked_at, not from when the report arrived.
func blockLifetime(p TemporaryBlacklistPayload, now time.Time) (time.Duration, bool) {
	if p.TTL <= 0 {
		return time.Duration(defaultExpireSeconds) * time.Second, true
	}
	started, ok := parseBlockTime(p.BlockedAt)
	if !ok {
		return time.Duration(p.TTL) * time.Second, true
	}
	expires := started.Add(time.Duration(p.TTL) * time.Second)
	if !expires.After(now) {
		return 0, false
	}
	return expires.Sub(now), true
}

func parseBlockTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if sec, err := strconv.ParseInt(raw, 10, 64); err == nil && sec > 0 {
		return time.Unix(sec, 0).UTC(), true
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
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
