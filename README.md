# Dorian Back-End

Go API server for the [Dorian Front-End](../dorian-front-end) dashboard. Manages protected servers, WAF/L4 rules, users, analytics, and agent communication.

## Features

- **Authentication** — login and bearer-token API access
- **Servers** — CRUD, deployment, license management, and per-server settings
- **WAF** — whitelist/blacklist, geo-location, anti-CC, rate limits, user-agent rules, and more
- **Layer 4** — firewall data, whitelist/blacklist, live attack tracking
- **Analytics** — traffic, bandwidth, security events, and Layer 4 attack statistics
- **Dashboard** — summary metrics and real-time security event feeds
- **Background workers** — periodic IP request stats collection from remote agents

## Tech Stack

- [Go 1.22+](https://go.dev/)
- [MySQL](https://www.mysql.com/) — primary data store
- [Redis](https://redis.io/) — blacklist and ephemeral data
- [gorilla/websocket](https://github.com/gorilla/websocket) — real-time connections

## Prerequisites

- **Go 1.22+** (see `go.mod`) 
- **MySQL** with the `cdnproxy` database (schema below)
- **Redis** running on `127.0.0.1:6379` by default

Ubuntu ships Go 1.18 by default, which is too old for this project. Install a current Go release:

```sh
# Example: install Go 1.22 to /usr/local/go
wget -qO /tmp/go.tar.gz https://go.dev/dl/go1.22.12.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH="/usr/local/go/bin:$PATH"
go version
```

Add `export PATH="/usr/local/go/bin:$PATH"` to your shell profile to make it permanent.

## Run Locally

```sh
cd /home/dorian/dorian-back-end
go run ./cmd/server
```

The server listens on `:8080` by default.

### With the front-end

```sh
# Terminal 1 — back-end
DB_USER=your_user DB_PASSWORD=your_password ALLOWED_ORIGINS=http://localhost:5173 go run ./cmd/server

# Terminal 2 — front-end (in dorian-front-end/)
VITE_API_BASE_URL=http://localhost:8080 npm run dev
```

## Configuration

Settings can be provided via environment variables or `config.json` (gitignored). Environment variables override `config.json` values.

### Server

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | HTTP listen port |
| `ALLOWED_ORIGINS` | *(all)* | Comma-separated CORS origins; unset allows all |
| `CONFIG_FILE` | `config.json` | Path to JSON config file |

### Database

| Variable | Default | Description |
|---|---|---|
| `DB_USER` | `root` | MySQL username |
| `DB_PASSWORD` | *(empty)* | MySQL password |
| `DB_HOST` | `127.0.0.1` | MySQL host |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `cdnproxy` | MySQL database name |
| `DB_DSN` | — | Full MySQL DSN (overrides individual DB settings) |

### Redis

| Variable | Default | Description |
|---|---|---|
| `REDIS_ADDR` | `127.0.0.1:6379` | Redis address |
| `REDIS_PASSWORD` | *(empty)* | Redis password |

### Agent & deployment

| Variable | Default | Description |
|---|---|---|
| `AGENT_SCHEME` | `http` | Scheme for remote agent calls |
| `AGENT_PORT` | `5000` | Remote agent port |
| `AGENT_TOKEN` | — | Bearer token for agent API |
| `AGENT_TIMEOUT_SECONDS` | `3` | Agent request timeout |
| `DEPLOY_LICENSE_BASE_URL` | `http://127.0.0.1:9090` | License deployment service URL |
| `DEPLOY_LICENSE_TIMEOUT_SECONDS` | `900` | Deploy operation timeout |

### Metrics collection

| Variable | Default | Description |
|---|---|---|
| `METRICS_PORT` | `9000` | Port on remote servers for metrics |
| `METRICS_POLL_INTERVAL_SECONDS` | `30` | Stats collection interval |
| `METRICS_BUCKET_PATH` | `/ip_request_stats` | IP request stats endpoint |
| `METRICS_*_BUCKET_PATH` | *(various)* | Other metrics bucket paths (ISP, country, referer, URL, user-agent) |

### Config file example

Create `config.json` in the project root:

```json
{
  "port": "8080",
  "allowedOrigins": ["http://localhost:5173"],
  "dbUser": "dorian",
  "dbPassword": "secret",
  "dbHost": "127.0.0.1",
  "dbPort": "3306",
  "dbName": "cdnproxy",
  "redisAddr": "127.0.0.1:6379"
}
```

## Database Schema

```sql
CREATE DATABASE IF NOT EXISTS cdnproxy;

CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NULL,
  role ENUM('Admin','User') NOT NULL,
  status ENUM('Waiting','Active','Block') NOT NULL,
  created DATETIME NULL
);

CREATE TABLE IF NOT EXISTS servers (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(255),
  ip VARCHAR(255),
  status ENUM('Normal','Pause','Expired'),
  service_status VARCHAR(32) NULL COMMENT 'angelos.service — shown as Angelos in UI',
  l4_status VARCHAR(32) NULL COMMENT 'sparta.service — L4 dot',
  l7_status VARCHAR(32) NULL COMMENT 'athens.service — L7 dot',
  license_type ENUM('Trial','L4','L7','Unified'),
  license_file VARCHAR(1024),
  version VARCHAR(50),
  os VARCHAR(64) NULL COMMENT 'Target OS label from product build, e.g. ubuntu-22.04',
  ssh_user VARCHAR(64),
  ssh_password VARCHAR(255),
  ssh_port INT,
  token VARCHAR(255),
  created DATETIME,
  expired DATETIME
);

CREATE TABLE IF NOT EXISTS server_users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  server_id BIGINT NOT NULL,
  user_id BIGINT NOT NULL,
  UNIQUE KEY unique_membership (server_id, user_id),
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS blacklist (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  server_id BIGINT NOT NULL,
  ip_address VARCHAR(255) NOT NULL,
  geolocation VARCHAR(255),
  reason VARCHAR(512),
  url VARCHAR(1024),
  server VARCHAR(255),
  ttl VARCHAR(128),
  trigger_rule VARCHAR(128),
  created_at DATETIME,
  expire_at DATETIME,
  updated_at DATETIME,
  FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE
);
```

If the `blacklist` table already exists without a `url` column:

```sql
ALTER TABLE blacklist ADD COLUMN url VARCHAR(1024) NULL AFTER reason;
```

### Migrations for existing databases

If the API logs `Unknown column 'l4_status'` or `failed to load servers`, apply in order:

```bash
mysql -u USER -p YOUR_DATABASE < scripts/add_servers_service_status.sql
mysql -u USER -p YOUR_DATABASE < scripts/add_servers_layer_status.sql
mysql -u USER -p YOUR_DATABASE < scripts/update_servers_license_type_enum.sql
```

Additional scripts in `scripts/`:

- `add_servers_os.sql` — adds `os` column to servers
- `add_geo_countries_block_mode.sql` — geo-location block mode support

`scripts/add_servers_layer_status.sql` is idempotent (adds `service_status`, `l4_status`, `l7_status` only when missing).

## API Overview

Most routes are available both with and without the `/api/v1` prefix.

| Area | Routes |
|---|---|
| Health | `GET /health`, `GET /api/v1/health`, `GET /api/v1/status` |
| Auth | `POST /auth/login` |
| Users | `GET/POST /users`, `GET/PUT/PATCH/DELETE /users/:id` |
| Servers | `GET/POST /servers`, `GET/PUT/PATCH/DELETE /servers/:id`, nested WAF/L4/upstream routes |
| Blacklist | `GET/POST /servers/blacklist`, `DELETE /servers/blacklist/:id` |
| Dashboard | `GET /dashboard/summary`, `/dashboard/security-events`, `/dashboard/bandwidth*` |
| Analytics | `GET /analytics/summary`, `/analytics/series/*`, `/analytics/security/*`, `/analytics/l4/*` |
| Agent reports | `POST /report_xdp`, `POST /api/temporary_blacklist_added` |
| Deploy | `GET /api/v1/deploy-versions` |

## Project Structure

```
cmd/server/          # Application entry point
internal/
├── api/             # HTTP handlers, routing, middleware
├── config/          # Configuration loading (env + JSON)
├── db/              # MySQL and Redis connections
├── store/           # Database access layers
├── worker/          # Background jobs (metrics collection)
├── remotesvc/       # Remote service probing
└── data/            # Static seed data
scripts/             # SQL migration scripts
```

## Build

```sh
go build -o bin/server ./cmd/server
./bin/server
```

## License

Private — not for public distribution.
