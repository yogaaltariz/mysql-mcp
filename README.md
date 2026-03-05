# MySQL MCP Server

A production-grade MCP server that connects Claude to multiple MySQL Docker containers on a VPS. All connections are defined in a single JSON file. Each connection can optionally manage its own SSH tunnel — no `autossh`, no systemd services, no external tooling required.

---

## How it works

```
Claude Desktop
     │
     └── mysql_mcp  (one process)
              ├── "app"       → SSH tunnel → VPS:3306 (app_db)       writes ON
              ├── "analytics" → SSH tunnel → VPS:3307 (analytics_db) read-only
              └── "legacy"    → SSH tunnel → VPS:3308 (legacy_db)    read-only
```

On startup the server:
1. Reads `connections.json` (or another configured path — see below)
2. Spawns one SSH tunnel per connection that has `ssh_host`
3. Blocks until each tunnel's local port accepts TCP connections
4. Opens a MySQL connection pool through each tunnel
5. Starts a background watcher per tunnel that auto-reconnects if SSH dies

---

## Security features

| Feature | Details |
|---|---|
| **SQL injection defence** | Blocks `SLEEP`, `BENCHMARK`, `LOAD_FILE`, `INTO OUTFILE`, block comments, stacked dangerous statements |
| **Forbidden statements** | `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, `FLUSH`, `SHUTDOWN` — always blocked |
| **Write guard per connection** | `allow_writes: false` by default — opt-in per connection |
| **Schema allowlist** | `allowed_dbs` restricts accessible schemas per connection |
| **TLS per connection** | Configure TLS independently per container |
| **Rate limiting** | Per-connection sliding 60s window (default 120 req/min) |
| **Query timeout** | Cancels runaway queries server-side (default 30s) |
| **Row cap** | Hard ceiling on rows returned per query (default 500) |
| **Identifier sanitisation** | DB/table names validated against `[a-zA-Z0-9_-]` only |
| **No secrets in code** | All credentials live in `connections.json`, never in source |
| **Config validation** | Missing/invalid fields caught at startup with clear error messages |

---

## SSH tunnel manager

The built-in tunnel manager replaces `autossh`. It:

- Spawns `ssh -N -L ...` as a subprocess with `ExitOnForwardFailure=yes` and `ServerAliveInterval`
- Blocks startup until the local port actually accepts a TCP connection (15s timeout)
- Runs a background watcher task per tunnel
- Reconnects with **exponential backoff** when SSH dies — delay doubles per failure, capped at `ssh_max_delay`
- Resets the MySQL connection pool after a successful reconnect so stale connections don't linger
- Returns a clear `"tunnel is reconnecting — please try again shortly"` error during reconnects
- Terminates cleanly on shutdown (SIGTERM → 3s grace → SIGKILL)

---

## Quick start

### 1. Docker Compose on your VPS

Bind each container to a **different port** on `127.0.0.1` — never `0.0.0.0`:

```yaml
# docker-compose.yml
services:
  mysql-app:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${APP_ROOT_PW}
      MYSQL_DATABASE: app_db
    ports:
      - "127.0.0.1:3306:3306"
    volumes:
      - app_data:/var/lib/mysql

  mysql-analytics:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${ANALYTICS_ROOT_PW}
      MYSQL_DATABASE: analytics_db
    ports:
      - "127.0.0.1:3307:3306"
    volumes:
      - analytics_data:/var/lib/mysql

  mysql-legacy:
    image: mysql:8.0
    restart: unless-stopped
    environment:
      MYSQL_ROOT_PASSWORD: ${LEGACY_ROOT_PW}
    ports:
      - "127.0.0.1:3308:3306"
    volumes:
      - legacy_data:/var/lib/mysql

volumes:
  app_data:
  analytics_data:
  legacy_data:
```

### 2. Create least-privilege MySQL users

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

### 3. Set up SSH key auth on the VPS

```bash
# Generate a dedicated key for the MCP server (no passphrase — it runs unattended)
ssh-keygen -t ed25519 -f ~/.ssh/mcp_vps -C "mysql-mcp" -N ""

# Copy the public key to the VPS
ssh-copy-id -i ~/.ssh/mcp_vps.pub ubuntu@your-vps.example.com

# Verify it works without a password prompt
ssh -i ~/.ssh/mcp_vps -o BatchMode=yes ubuntu@your-vps.example.com echo ok
```

### 4. Install the MCP server locally

```bash
cd mysql-mcp
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 5. Create your connections file

```bash
cp connections.example.json connections.json
$EDITOR connections.json        # fill in your VPS hostname, passwords, key path
```

The file is plain JSON with `//` and `#` line comments supported:

```jsonc
// connections.json
[
  {
    "name":            "app",
    "label":           "App Database",
    "host":            "127.0.0.1",
    "port":            13306,
    "user":            "mcp_app",
    "password":        "strong_password_1",
    "database":        "app_db",
    "allow_writes":    true,
    "allowed_dbs":     ["app_db"],

    // SSH tunnel — managed automatically by the MCP server
    "ssh_host":        "your-vps.example.com",
    "ssh_user":        "ubuntu",
    "ssh_key":         "/home/you/.ssh/mcp_vps",
    "ssh_remote_port": 3306,
    "ssh_local_port":  13306
  },
  {
    "name":            "analytics",
    "label":           "Analytics Database",
    "host":            "127.0.0.1",
    "port":            13307,
    "user":            "mcp_analytics",
    "password":        "strong_password_2",
    "database":        "analytics_db",
    "allowed_dbs":     ["analytics_db"],
    "max_rows":        1000,

    "ssh_host":        "your-vps.example.com",
    "ssh_user":        "ubuntu",
    "ssh_key":         "/home/you/.ssh/mcp_vps",
    "ssh_remote_port": 3307,
    "ssh_local_port":  13307
  },
  {
    "name":            "legacy",
    "label":           "Legacy Database",
    "host":            "127.0.0.1",
    "port":            13308,
    "user":            "mcp_legacy",
    "password":        "strong_password_3",
    "allowed_dbs":     ["legacy_db", "archive_db"],

    "ssh_host":        "your-vps.example.com",
    "ssh_user":        "ubuntu",
    "ssh_key":         "/home/you/.ssh/mcp_vps",
    "ssh_remote_port": 3308,
    "ssh_local_port":  13308
  }
]
```

### 6. Configure Claude Desktop

`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
`%APPDATA%\Claude\claude_desktop_config.json` (Windows)

```json
{
  "mcpServers": {
    "mysql": {
      "command": "/absolute/path/to/mysql-mcp/.venv/bin/python",
      "args":    ["/absolute/path/to/mysql-mcp/server.py"],
      "env": {
        "MYSQL_CONFIG": "/absolute/path/to/mysql-mcp/connections.json"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

---

## Where the config file is loaded from

The server searches these locations in order and uses the first one found:

| Priority | Source |
|---|---|
| 1 | Path in `MYSQL_CONFIG` environment variable |
| 2 | `connections.json` in the working directory |
| 3 | `~/.mysql-mcp/connections.json` |
| 4 | `/etc/mysql-mcp/connections.json` |
| 5 | Inline JSON in `MYSQL_CONNECTIONS` env var *(legacy / CI fallback)* |

---

## All connection fields

### MySQL fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `name` | string | ✓ | — | Unique identifier (`[a-zA-Z0-9_-]` only) |
| `host` | string | ✓ | — | MySQL host (usually `127.0.0.1` when tunnelling) |
| `user` | string | ✓ | — | MySQL username |
| `password` | string | ✓ | — | MySQL password |
| `port` | int | | `3306` | MySQL port |
| `label` | string | | `name` | Human-readable display name |
| `database` | string | | `null` | Default schema |
| `use_tls` | bool | | `false` | Enforce TLS on the MySQL connection |
| `ssl_ca` | string | | `null` | Path to CA certificate (recommended with TLS) |
| `ssl_cert` | string | | `null` | Path to client cert (mutual TLS) |
| `ssl_key` | string | | `null` | Path to client key (mutual TLS) |
| `allow_writes` | bool | | `false` | Allow `INSERT`/`UPDATE`/`DELETE`/`CREATE`/`ALTER` |
| `allowed_dbs` | `[string]` | | `[]` | Schema whitelist — empty means all visible schemas |
| `max_rows` | int | | `500` | Max rows returned per query |
| `query_timeout` | int | | `30` | Query timeout in seconds |
| `rate_limit` | int | | `120` | Max queries per minute |

### SSH tunnel fields

All optional. Omit the `ssh_*` fields entirely if MySQL is already reachable without a tunnel.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `ssh_host` | string | ✓ to enable | — | VPS hostname or IP |
| `ssh_port` | int | | `22` | SSH port on the VPS |
| `ssh_user` | string | | system default | SSH login username |
| `ssh_key` | string | | — | Path to SSH private key (strongly preferred over password) |
| `ssh_password` | string | | — | SSH password |
| `ssh_remote_host` | string | | `127.0.0.1` | MySQL host as seen from the VPS |
| `ssh_remote_port` | int | | same as `port` | MySQL port as seen from the VPS |
| `ssh_local_port` | int | ✓ if `ssh_host` set | — | Local port the tunnel binds to |
| `ssh_keepalive` | int | | `30` | `ServerAliveInterval` in seconds |
| `ssh_retry_delay` | int | | `5` | Initial reconnect wait in seconds |
| `ssh_max_delay` | int | | `60` | Max reconnect wait — exponential backoff ceiling |

---

## Available tools

| Tool | Description |
|---|---|
| `mysql_list_instances` | List all connections with config and live tunnel state — **call this first** |
| `mysql_query` | Execute SQL on a named connection |
| `mysql_list_databases` | List schemas visible on a connection |
| `mysql_list_tables` | List tables and views in a schema |
| `mysql_describe_table` | Full schema: columns, indexes, `CREATE TABLE` DDL |
| `mysql_explain_query` | `EXPLAIN` a `SELECT` to inspect its execution plan |
| `mysql_server_status` | Version, uptime, connection counts, TLS status, tunnel state |

---

## What the logs look like

**Normal startup:**
```
[INFO] Loading connections from: /home/you/mysql-mcp/connections.json
[INFO] Connection 'app' (App Database): mysql=127.0.0.1:13306 db=app_db writes=True tunnel=your-vps.example.com:13306
[INFO] Starting 3 SSH tunnel(s)…
[INFO] SSH tunnel 'app' ready on 127.0.0.1:13306 (connect #1)
[INFO] SSH tunnel 'analytics' ready on 127.0.0.1:13307 (connect #1)
[INFO] SSH tunnel 'legacy' ready on 127.0.0.1:13308 (connect #1)
[INFO] MySQL pool ready for 'app' (127.0.0.1:13306)
[INFO] MySQL pool ready for 'analytics' (127.0.0.1:13307)
[INFO] MySQL pool ready for 'legacy' (127.0.0.1:13308)
[INFO] All connections ready ✓
```

**Tunnel drops and reconnects:**
```
[WARNING] SSH tunnel 'app' died (exit 255). Reconnecting in 5s…
[WARNING] SSH stderr for 'app': Connection to your-vps.example.com closed.
[INFO]    SSH tunnel 'app' ready on 127.0.0.1:13306 (connect #2)
```

**Query during reconnect:**
```json
{ "error": "SSH tunnel for 'app' is reconnecting — please try again shortly." }
```

---

## Adding a new container later

Add one more object to `connections.json` and restart the MCP server. No code changes:

```jsonc
{
  "name":            "warehouse",
  "label":           "Data Warehouse",
  "host":            "127.0.0.1",
  "port":            13309,
  "user":            "mcp_warehouse",
  "password":        "strong_password_4",
  "database":        "warehouse_db",
  "allowed_dbs":     ["warehouse_db"],
  "ssh_host":        "your-vps.example.com",
  "ssh_user":        "ubuntu",
  "ssh_key":         "/home/you/.ssh/mcp_vps",
  "ssh_remote_port": 3309,
  "ssh_local_port":  13309
}
```

---

## Production checklist

- [ ] `connections.json` is in `.gitignore` and never committed
- [ ] Each MySQL user has only the minimum required privileges
- [ ] `allow_writes: false` for every read-only connection
- [ ] `allowed_dbs` set for every connection to restrict schema access
- [ ] All Docker containers bound to `127.0.0.1` on the VPS — not `0.0.0.0`
- [ ] A dedicated SSH key with no passphrase is used (`ssh-keygen -t ed25519`)
- [ ] All MySQL passwords are strong and randomly generated
- [ ] `max_rows` and `query_timeout` are tuned per connection's workload
- [ ] `ssh_keepalive: 30` (default) detects dead connections within ~90s
