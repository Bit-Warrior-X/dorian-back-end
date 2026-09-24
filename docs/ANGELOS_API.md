# Dorian Back-End ↔ Angelos API

Contract for HTTP calls from the **Dorian control-plane back-end** to the **Angelos** edge agent (`api_parser` / `angelos.service`) on each protected host.

The Vue front-end never talks to Angelos. Dashboard mutations hit Dorian; Dorian pushes JSON to the edge.

Machine-readable OpenAPI 3.0: [`../angelos_api.yml`](../angelos_api.yml)

Source of truth in code:

- L7 push helpers — `internal/api/l7_site_push.go`
- L7 temporary blacklist — `internal/api/handlers.go`
- L4 client — `internal/api/agent_client.go`

---

## Overview

```
┌─────────────────┐     JWT / panel API      ┌──────────────────┐
│  Dorian Front   │ ───────────────────────► │  Dorian Back-End │
└─────────────────┘                          └────────┬─────────┘
                                                      │
                         POST application/json        │
                         http://{edge-ip}:5000/API/…  │
                                                      ▼
                                             ┌─────────────────┐
                                             │ Angelos :5000   │
                                             │ (api_parser)    │
                                             └────────┬────────┘
                                                      │
                                    configures Athens (L7) / Sparta (L4)
```

| Item | Value |
|------|--------|
| Base URL | `http://{edge-server-ip}:5000` |
| Default port | `5000` (`AGENT_PORT` / `agentPort`) |
| Scheme | `http` by default (`AGENT_SCHEME` / `agentScheme`) |
| Method | **POST** for all endpoints in this document |
| Content-Type | `application/json` |
| Success | HTTP **2xx** (body may be empty or JSON) |
| Failure | Non-2xx → Dorian typically returns **502** to the panel |

### Scope

| Scope | Behavior |
|-------|----------|
| **Site-scoped** | Dorian POSTs once **per edge** assigned to the site. Payload includes that edge’s `serverId` / `server_id`. |
| **Server-scoped** | Single POST to one edge IP (listening ports, L4, temporary blacklist). |

### Authentication

| Layer | Behavior |
|-------|----------|
| **L7** | No agent token in current L7 push helpers — JSON body only. |
| **L4** | Body field `token` = edge `servers.token` (falls back to `AGENT_TOKEN`). Optional header `Authorization: Bearer {AGENT_TOKEN}` when configured. |

---

## Endpoint catalog

### L7 — WAF

| Path | Scope | When Dorian calls it |
|------|-------|----------------------|
| `POST /API/L7/l7_update_whitelist` | Site | WAF whitelist create/update/delete |
| `POST /API/L7/l7_update_blacklist` | Site | WAF blacklist mutations |
| `POST /API/L7/l7_update_geolocation` | Site | Geo rules (ENABLE only) |
| `POST /API/L7/l7_update_antiheader` | Site | Anti-header rules |
| `POST /API/L7/l7_update_intervalfreqlimit` | Site | Interval frequency limits |
| `POST /API/L7/l7_update_secondfreqlimit` | Site | Per-second frequency limits |
| `POST /API/L7/l7_update_responsefreq` | Site | Response-code frequency limits |
| `POST /API/L7/l7_update_useragent` | Site | User-agent rules |
| `POST /API/L7/l7_update_temporaryblacklist` | Server | Edge reports / control-plane temp blacklist sync |

Anti-CC rules are included inside `l7_update_site` (`waf_rules.waf_anticc`); there is no separate incremental Anti-CC push path today.

**Typical WAF rule payload shape** (whitelist example):

```json
{
  "serverId": 1033,
  "siteId": 55,
  "serverIp": "203.0.113.10",
  "rules": [
    {
      "id": 101,
      "wafRuleId": 42,
      "ips": "192.168.1.0/24,10.0.0.5",
      "url": "/*",
      "method": "GET,POST",
      "description": "Office network bypass"
    }
  ]
}
```

Field names for other WAF endpoints follow the same envelope (`serverId`, `siteId`, `serverIp`, `rules`) with rule-specific properties — see OpenAPI schemas.

---

### L7 — Site lifecycle & traffic

| Path | Scope | When Dorian calls it |
|------|-------|----------------------|
| `POST /API/L7/l7_update_site` | Site | Site create/update — **full** site config push |
| `POST /API/L7/l7_update_domain` | Site | Domain rename (`old_domain` → `new_domain`) |
| `POST /API/L7/l7_delete_site` | Site | Site removed from panel (HTTP **404** = outdated Angelos → warning only) |
| `POST /API/L7/l7_update_upstreamservers` | Site | Upstream origin list changed |
| `POST /API/L7/l7_update_listeningports` | Server | Edge listening ports changed |
| `POST /API/L7/l7_update_site_listeningports` | Server | Site↔port selection changed |
| `POST /API/L7/l7_update_compress` | Site | Gzip MIME settings changed |
| `POST /API/L7/l7_update_cacherules` | Site | Cache rules changed |
| `POST /API/L7/l7_clear_cache` | Site | Clear all cache for site |
| `POST /API/L7/l7_clear_url_cache` | Site | Clear cache by URL match |

**Full site push** (`l7_update_site`) — snake_case keys:

```json
{
  "server_id": 1033,
  "site_id": 55,
  "domain": "www.example.com",
  "ssl": {
    "ssl_type": "custom",
    "ssl_cert": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----",
    "ssl_cert_key": "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----"
  },
  "waf_rules": {
    "waf_rule_id": 42,
    "waf_whitelist": [],
    "waf_blacklist": [],
    "waf_geolocation": [],
    "waf_anticc": [],
    "waf_antiheader": [],
    "waf_intervalfreqlimit": [],
    "waf_secondfreqlimit": [],
    "waf_responsefreq": [],
    "waf_useragent": []
  },
  "compress_settings": {
    "css": true,
    "html": true,
    "js": true,
    "audio": false,
    "font": true,
    "applications": false
  },
  "cache_rules": [],
  "http_ports": [],
  "https_ports": [],
  "upstream_servers": [
    {
      "id": 12,
      "serverId": 1033,
      "ip_port": "10.10.0.5:8080",
      "protocol": "http",
      "description": "Primary origin"
    }
  ]
}
```

**Delete site:**

```json
{
  "server_id": 1033,
  "site_id": 55,
  "domain": "www.example.com"
}
```

**Domain update:**

```json
{
  "server_id": 1033,
  "site_id": 55,
  "old_domain": "old.example.com",
  "new_domain": "www.example.com"
}
```

**Clear URL cache:**

```json
{
  "serverId": 1033,
  "siteId": 55,
  "serverIp": "203.0.113.10",
  "match_type": "wildcard",
  "match_content": "www.example.com/*/api/*"
}
```

---

### L4 — Firewall (Sparta via Angelos)

Default paths (overridable via config):

| Path | Config key | Purpose |
|------|------------|---------|
| `POST /API/L4/l4_firewall_data` | `agentL4Path` / `AGENT_L4_PATH` | Push full L4 XDP config |
| `POST /API/L4/options` | `agentL4OptionsPath` / `AGENT_L4_OPTIONS_PATH` | List NICs + attach modes |
| `POST /API/L4/add_white_ip` | — | Add whitelist IP |
| `POST /API/L4/remove_white_ip` | — | Remove whitelist IP |
| `POST /API/L4/remove_white_ip_all` | — | Clear whitelist |
| `POST /API/L4/add_block_ip` | — | Add blacklist IP |
| `POST /API/L4/remove_block_ip` | — | Remove blacklist IP |
| `POST /API/L4/remove_block_ip_all` | — | Clear blacklist |

**Auth body** (options / clear-all):

```json
{ "token": "edge-agent-token-example" }
```

**Add/remove single IP:**

```json
{
  "token": "edge-agent-token-example",
  "ip": "198.51.100.77"
}
```

**L4 config push** — `token` plus L4 fields from `store.L4Config` (device, attach mode, SYN/ACK/UDP/ICMP thresholds, geo, connection limits, …). Full field list: OpenAPI schema `L4ConfigPush`.

**Options response example:**

```json
{
  "interfaces": ["eth0", "eth1"],
  "attachModes": ["native", "skb", "drv"],
  "attachModesByInterface": {
    "eth0": ["native", "skb"],
    "eth1": ["skb"]
  }
}
```

---

## Error handling

| Situation | Angelos | Dorian behavior |
|-----------|---------|-----------------|
| Apply OK | `2xx` | Continue |
| Apply failed | `4xx` / `5xx` | Log body (truncated); panel often gets **502** |
| `l7_delete_site` / `l7_update_domain` on old agent | `404` | Treated as **warning** (site still removed/updated in DB) |
| Timeout | TCP/HTTP timeout | Default agent timeout **5s** (`AGENT_TIMEOUT_SECONDS`) |

L4 client wraps non-2xx as `AgentResponseError` with status + body snippet.

---

## Dorian reverse direction (edge → control plane)

Not Angelos “outbound API”, but related edge callbacks the back-end exposes:

| Panel / API path | Purpose |
|------------------|---------|
| `POST /report_xdp` | L4 attack / XDP reports |
| `POST /api/temporary_blacklist_added` | Temporary blacklist notified from edge |
| `POST /api/report_edge_configure` | Periodic full edge configure snapshot (L4 lists/config, listening ports, temp blacklist, site compress/upstreams/ports) |

Angelos posts `report_edge_configure` about every 60s (`EDGE_LIST_SYNC_INTERVAL`). Dorian authenticates with the edge `token` and reconciles MySQL/Redis for that server so panel and edge stay aligned.

After ingest of a one-shot temp-blacklist event, Dorian may also call Angelos `l7_update_temporaryblacklist` to keep L7 in sync.

---

## Configuration reference

| Env / JSON | Default | Role |
|------------|---------|------|
| `AGENT_SCHEME` / `agentScheme` | `http` | URL scheme to edge |
| `AGENT_PORT` / `agentPort` | `5000` | Angelos listen port |
| `AGENT_TOKEN` / `agentToken` | *(empty)* | Optional bearer + L4 token fallback |
| `AGENT_L4_PATH` / `agentL4Path` | `/API/L4/l4_firewall_data` | L4 config path |
| `AGENT_L4_OPTIONS_PATH` / `agentL4OptionsPath` | `/API/L4/options` | L4 options path |
| `AGENT_TIMEOUT_SECONDS` / `agentTimeoutSeconds` | `5` | HTTP client timeout |

Per-edge credentials: `servers.ip`, `servers.token`.

---

## Quick test from the control plane

```sh
EDGE=203.0.113.10
TOKEN='edge-token-from-servers-table'

# L4 options
curl -sS -X POST "http://${EDGE}:5000/API/L4/options" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"${TOKEN}\"}"

# L7 clear cache (example site-scoped body)
curl -sS -X POST "http://${EDGE}:5000/API/L7/l7_clear_cache" \
  -H 'Content-Type: application/json' \
  -d '{"serverId":1033,"siteId":55,"serverIp":"203.0.113.10"}'
```

---

## Maintaining this document

1. Prefer updating [`angelos_api.yml`](../angelos_api.yml) schemas when payloads change.
2. Keep this Markdown catalog in sync when adding/removing paths in `l7_site_push.go` or `agent_client.go`.
3. OpenAPI can be previewed with Swagger UI / Redoc against `angelos_api.yml`.
