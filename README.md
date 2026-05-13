
# vue-project-backend

Go backend for the Vue project. Provides simple auth and server APIs that
match the frontend expectations.

## Requirements

- Go 1.22+

## Run locally

```sh
cd /home/vue-project-backend
go run ./cmd/server
```

The server listens on `:8080` by default.

## Environment

- `PORT` (default: `8080`)
- `ALLOWED_ORIGINS` (comma-separated list of allowed origins; if unset, allows all)
- `DB_USER` (default: `root`)
- `DB_PASSWORD` (default: empty)
- `DB_HOST` (default: `127.0.0.1`)
- `DB_PORT` (default: `3306`)
- `DB_NAME` (default: `cdnproxy`)
- `DB_DSN` (optional full MySQL DSN; overrides individual DB settings)
- `CONFIG_FILE` (optional; defaults to `config.json`)

Example:

```sh
PORT=8080 ALLOWED_ORIGINS=http://localhost:5173 go run ./cmd/server
```

## Config file

Backend can read `config.json` by default (or `CONFIG_FILE` if set). Env vars
override config file values.

## Database schema

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
  license_type ENUM('Trial','L4','L7','Unified'),
  license_file VARCHAR(1024),
  version VARCHAR(50),
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

If the `blacklist` table already exists without a `url` column, add it with:

```sql
ALTER TABLE blacklist ADD COLUMN url VARCHAR(1024) NULL AFTER reason;
```

## Endpoints

- `POST /auth/login`
  - body: `{ "email": "...", "password": "..." }`
  - response: `{ "token": "mock-token", "user": { "email": "..." } }`
- `GET /servers`
- `GET /users`
- `POST /users`
- `PUT /users/:id`
- `PATCH /users/:id`
- `DELETE /users/:id`
- `GET /health`
- `GET /api/v1/health`
- `GET /api/v1/status`

