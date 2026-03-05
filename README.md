# MySQL MCP Server — Multi-Instance Setup Guide

One MCP server. Multiple MySQL Docker containers. All connections defined in
a **single JSON array** — no per-instance env var prefixes, no code changes
to add or remove a container.

---

## Configuration format

Set one environment variable:

```bash
MYSQL_CONNECTIONS='[
  {
    "name":         "app",
    "label":        "App Database",
    "host":         "127.0.0.1",
    "port":         13306,
    "user":         "mcp_app",
    "password":     "secret1",
    "database":     "app_db",
    "allow_writes": true,
    "allowed_dbs":  ["app_db"]
  },
  {
    "name":         "analytics",
    "host":         "127.0.0.1",
    "port":         13307,
    "user":         "mcp_analytics",
    "password":     "secret2",
    "database":     "analytics_db",
    "allowed_dbs":  ["analytics_db"],
    "max_rows":     1000
  },
  {
    "name":    "legacy",
    "host":    "127.0.0.1",
    "port":    13308,
    "user":    "mcp_legacy",
    "password":"secret3",
    "allowed_dbs": ["legacy_db", "archive_db"]
  }
]'
```

### All connection fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | ✓ | — | Unique identifier (letters/digits/`_`/`-`) |
| `host` | string | ✓ | — | Hostname or IP of the container |
| `user` | string | ✓ | — | MySQL username |
| `password` | string | ✓ | — | MySQL password |
| `port` | int | | 3306 | MySQL port |
| `label` | string | | name | Human-readable display name |
| `database` | string | | null | Default schema |
| `use_tls` | bool | | false | Enforce TLS |
| `ssl_ca` | string | | null | Path to CA cert (recommended with TLS) |
| `ssl_cert` | string | | null | Client cert path (mutual TLS) |
| `ssl_key` | string | | null | Client key path (mutual TLS) |
| `allow_writes` | bool | | false | Allow INSERT/UPDATE/DELETE/CREATE/ALTER |
| `allowed_dbs` | [string] | | [] | Schema whitelist (empty = all visible) |
| `max_rows` | int | | 500 | Row cap per query |
| `query_timeout` | int | | 30 | Timeout in seconds |
| `rate_limit` | int | | 120 | Max queries per minute |

---

## Security features

| Feature | Details |
|---|---|
| **Per-connection isolation** | Each container gets its own pool, rate limiter, and settings |
| **SQL injection defence** | SLEEP, BENCHMARK, INTO OUTFILE, block comments, stacked statements blocked |
| **Forbidden statements** | DROP, TRUNCATE, GRANT, REVOKE, FLUSH, SHUTDOWN always blocked |
| **Write guard** | `allow_writes: false` by default — opt-in per connection |
| **Schema allowlist** | `allowed_dbs` restricts which schemas can be accessed |
| **TLS per connection** | Configure TLS independently per container |
| **Identifier sanitisation** | DB/table names validated against `[a-zA-Z0-9_-]` |
| **JSON validation** | Missing/invalid fields caught at startup with clear errors |

---

## 1 — Docker Compose on your VPS

Bind each container to a **different host port** and only to `127.0.0.1`:

```yaml
services:
  mysql-app:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${APP_ROOT_PW}
      MYSQL_DATABASE: app_db
    ports:
      - "127.0.0.1:3306:3306"   # ← never 0.0.0.0

  mysql-analytics:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${ANALYTICS_ROOT_PW}
      MYSQL_DATABASE: analytics_db
    ports:
      - "127.0.0.1:3307:3306"

  mysql-legacy:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${LEGACY_ROOT_PW}
    ports:
      - "127.0.0.1:3308:3306"
```

---

## 2 — Create least-privilege MySQL users

```sql
-- mysql-app (writes allowed)
CREATE USER 'mcp_app'@'%' IDENTIFIED BY 'strong_password_1';
GRANT SELECT, INSERT, UPDATE, DELETE, SHOW DATABASES, SHOW VIEW
  ON app_db.* TO 'mcp_app'@'%';

-- mysql-analytics (read-only)
CREATE USER 'mcp_analytics'@'%' IDENTIFIED BY 'strong_password_2';
GRANT SELECT, SHOW DATABASES, SHOW VIEW ON analytics_db.* TO 'mcp_analytics'@'%';

-- mysql-legacy (read-only, two schemas)
CREATE USER 'mcp_legacy'@'%' IDENTIFIED BY 'strong_password_3';
GRANT SELECT, SHOW DATABASES, SHOW VIEW ON legacy_db.*  TO 'mcp_legacy'@'%';
GRANT SELECT, SHOW DATABASES, SHOW VIEW ON archive_db.* TO 'mcp_legacy'@'%';

FLUSH PRIVILEGES;
```

---

## 3 — Install locally

```bash
cd mysql-mcp
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
$EDITOR .env    # fill in passwords
```

---

## 4 — SSH tunnels (recommended)

One `autossh` command opens all three tunnels:

```bash
autossh -M 0 -f -N \
  -L 13306:127.0.0.1:3306 \
  -L 13307:127.0.0.1:3307 \
  -L 13308:127.0.0.1:3308 \
  your_user@your-vps-ip
```

Then use `host: "127.0.0.1"` and the local ports in `MYSQL_CONNECTIONS`.

---

## 5 — Claude Desktop config

```json
{
  "mcpServers": {
    "mysql": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args":    ["/absolute/path/to/server.py"],
      "env": {
        "MYSQL_CONNECTIONS": "[{\"name\":\"app\",\"host\":\"127.0.0.1\",\"port\":13306,\"user\":\"mcp_app\",\"password\":\"secret1\",\"database\":\"app_db\",\"allow_writes\":true,\"allowed_dbs\":[\"app_db\"]},{\"name\":\"analytics\",\"host\":\"127.0.0.1\",\"port\":13307,\"user\":\"mcp_analytics\",\"password\":\"secret2\",\"database\":\"analytics_db\",\"allowed_dbs\":[\"analytics_db\"]},{\"name\":\"legacy\",\"host\":\"127.0.0.1\",\"port\":13308,\"user\":\"mcp_legacy\",\"password\":\"secret3\",\"allowed_dbs\":[\"legacy_db\",\"archive_db\"]}]"
      }
    }
  }
}
```

> Tip: It's cleaner to load `.env` and pass a script wrapper than to inline JSON in the claude_desktop_config. See below.

### Wrapper script approach (cleaner)

```bash
#!/bin/bash
# run_mcp.sh
set -a
source /absolute/path/to/mysql-mcp/.env
set +a
exec /absolute/path/to/.venv/bin/python /absolute/path/to/server.py
```

```json
{
  "mcpServers": {
    "mysql": {
      "command": "/absolute/path/to/run_mcp.sh"
    }
  }
}
```

---

## 6 — Available tools

| Tool | Description |
|---|---|
| `mysql_list_instances` | List all connections + config (call this first) |
| `mysql_query` | Execute SQL on a named connection |
| `mysql_list_databases` | List schemas on a connection |
| `mysql_list_tables` | List tables/views in a schema |
| `mysql_describe_table` | Full schema: columns, indexes, CREATE DDL |
| `mysql_explain_query` | EXPLAIN a SELECT for query plan analysis |
| `mysql_server_status` | Version, uptime, connections, TLS status |

---

## 7 — Adding a 4th container later

Just add one more object to `MYSQL_CONNECTIONS` — no code changes needed:

```json
{
  "name":     "warehouse",
  "host":     "127.0.0.1",
  "port":     13309,
  "user":     "mcp_warehouse",
  "password": "secret4",
  "database": "warehouse_db"
}
```

Restart the MCP server. Done.

---

## 8 — Production checklist

- [ ] Each MySQL user has only the minimum required privileges
- [ ] `allow_writes: false` for read-only connections
- [ ] `allowed_dbs` set for every connection
- [ ] All containers bound to `127.0.0.1` on the VPS
- [ ] SSH tunnels are persistent (autossh / systemd)
- [ ] `.env` is in `.gitignore`
- [ ] All passwords are strong and randomly generated
