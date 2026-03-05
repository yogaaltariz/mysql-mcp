"""
MySQL MCP Server — Multi-Instance, Production-Grade + Built-in SSH Tunnel Manager
==================================================================================
Connections are defined via a single JSON array in MYSQL_CONNECTIONS.
Each connection can optionally define SSH tunnel settings — the MCP server
will spawn, monitor, and auto-reconnect the tunnel itself.
No external autossh required.

─── Environment variables ───────────────────────────────────────────────────
  MYSQL_CONNECTIONS   JSON array of connection objects  (REQUIRED)

Each connection object:
  # MySQL connection (required)
  name            string   Unique name, e.g. "app"                   (required)
  host            string   MySQL host reachable after tunnel is up   (required)
  user            string   MySQL username                            (required)
  password        string   MySQL password                            (required)
  port            int      MySQL port (on the host above)            (default: 3306)
  database        string   Default schema                            (optional)
  label           string   Human-readable label                      (default: name)

  # MySQL safety settings
  use_tls         bool     Enforce TLS on MySQL connection           (default: false)
  ssl_ca          string   Path to CA cert                           (optional)
  ssl_cert        string   Path to client cert (mutual TLS)          (optional)
  ssl_key         string   Path to client key  (mutual TLS)          (optional)
  allow_writes    bool     Allow INSERT/UPDATE/DELETE/CREATE/ALTER   (default: false)
  allowed_dbs     [str]    Schema whitelist (empty = all visible)    (default: [])
  max_rows        int      Row cap per query                         (default: 500)
  query_timeout   int      Query timeout in seconds                  (default: 30)
  rate_limit      int      Max queries per minute                    (default: 120)

  # SSH tunnel (all optional — omit if you don't need a tunnel)
  ssh_host        string   VPS hostname or IP                        (optional)
  ssh_port        int      SSH port on the VPS                       (default: 22)
  ssh_user        string   SSH username                              (optional)
  ssh_key         string   Path to SSH private key file             (optional)
  ssh_password    string   SSH password (prefer key-based auth)     (optional)
  ssh_remote_host string   MySQL host as seen from the VPS          (default: 127.0.0.1)
  ssh_remote_port int      MySQL port as seen from the VPS          (default: same as port)
  ssh_local_port  int      Local port to bind the tunnel to         (required if ssh_host set)
  ssh_keepalive   int      ServerAliveInterval in seconds           (default: 30)
  ssh_retry_delay int      Initial reconnect wait in seconds        (default: 5)
  ssh_max_delay   int      Max reconnect wait (exponential backoff) (default: 60)

─── Example MYSQL_CONNECTIONS ───────────────────────────────────────────────
[
  {
    "name": "app",
    "label": "App Database",
    "host": "127.0.0.1",
    "port": 13306,
    "user": "mcp_app",
    "password": "secret1",
    "database": "app_db",
    "allow_writes": true,
    "allowed_dbs": ["app_db"],
    "ssh_host": "your-vps.example.com",
    "ssh_user": "ubuntu",
    "ssh_key": "/home/you/.ssh/id_ed25519",
    "ssh_remote_host": "127.0.0.1",
    "ssh_remote_port": 3306,
    "ssh_local_port": 13306
  },
  {
    "name": "analytics",
    "host": "127.0.0.1",
    "port": 13307,
    "user": "mcp_analytics",
    "password": "secret2",
    "database": "analytics_db",
    "ssh_host": "your-vps.example.com",
    "ssh_user": "ubuntu",
    "ssh_key": "/home/you/.ssh/id_ed25519",
    "ssh_remote_port": 3307,
    "ssh_local_port": 13307
  }
]
─────────────────────────────────────────────────────────────────────────────
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import signal
import ssl as _ssl
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, date, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

import aiomysql
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, field_validator, ConfigDict

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] mysql_mcp: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("mysql_mcp")


# ── SQL Safety ─────────────────────────────────────────────────────────────
_FORBIDDEN_PATTERN = re.compile(
    r"^\s*(DROP\s+(DATABASE|SCHEMA|TABLE|USER)|TRUNCATE|"
    r"ALTER\s+USER|GRANT|REVOKE|FLUSH|RESET|SHUTDOWN|"
    r"LOAD\s+DATA|INTO\s+OUTFILE|INTO\s+DUMPFILE|"
    r"CALL\s+mysql\.|INSTALL\s+PLUGIN|UNINSTALL\s+PLUGIN)",
    re.IGNORECASE,
)
_WRITE_PATTERN = re.compile(
    r"^\s*(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|RENAME)",
    re.IGNORECASE,
)
_INJECTION_PATTERNS = [
    re.compile(r";\s*(DROP|TRUNCATE|GRANT|REVOKE|FLUSH|SHUTDOWN)", re.IGNORECASE),
    re.compile(r"/\*.*?\*/", re.DOTALL),
    re.compile(r"xp_\w+", re.IGNORECASE),
    re.compile(r"\bSLEEP\s*\(", re.IGNORECASE),
    re.compile(r"\bBENCHMARK\s*\(", re.IGNORECASE),
    re.compile(r"\bWAITFOR\s+DELAY\b", re.IGNORECASE),
    re.compile(r"\bINTO\s+OUTFILE\b", re.IGNORECASE),
    re.compile(r"\bINTO\s+DUMPFILE\b", re.IGNORECASE),
    re.compile(r"\bLOAD_FILE\s*\(", re.IGNORECASE),
]
_SAFE_IDENTIFIER = re.compile(r"^[a-zA-Z0-9_\-]+$")


def _classify_query(sql: str, allow_writes: bool) -> Tuple[str, Optional[str]]:
    stripped = sql.strip()
    if not stripped:
        return "forbidden", "Empty query."
    if _FORBIDDEN_PATTERN.match(stripped):
        return "forbidden", "This statement type is not permitted for safety reasons."
    is_write = bool(_WRITE_PATTERN.match(stripped))
    for pat in _INJECTION_PATTERNS:
        if pat.search(stripped):
            return "forbidden", "Query contains patterns associated with SQL injection and was rejected."
    if is_write:
        if not allow_writes:
            return "forbidden", (
                "Write operations are disabled for this instance. "
                "Set allow_writes: true in MYSQL_CONNECTIONS to enable."
            )
        return "write", None
    return "read", None


# ── JSON helpers ───────────────────────────────────────────────────────────
def _json_default(obj: Any) -> Any:
    if isinstance(obj, (datetime, date)): return obj.isoformat()
    if isinstance(obj, timedelta):        return str(obj)
    if isinstance(obj, Decimal):          return float(obj)
    if isinstance(obj, bytes):            return obj.hex()
    raise TypeError(f"Not serializable: {type(obj)}")

def _to_json(data: Any) -> str:
    return json.dumps(data, default=_json_default, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════════════════
# SSH Tunnel Manager
# ══════════════════════════════════════════════════════════════════════════════

class TunnelState(Enum):
    STOPPED    = "stopped"
    CONNECTING = "connecting"
    CONNECTED  = "connected"
    RECONNECTING = "reconnecting"


@dataclass
class SshTunnelConfig:
    """SSH tunnel parameters extracted from a connection object."""
    ssh_host:        str
    ssh_port:        int   = 22
    ssh_user:        Optional[str] = None
    ssh_key:         Optional[str] = None
    ssh_password:    Optional[str] = None
    ssh_remote_host: str  = "127.0.0.1"
    ssh_remote_port: int  = 3306
    ssh_local_port:  int  = 13306
    ssh_keepalive:   int  = 30
    ssh_retry_delay: int  = 5
    ssh_max_delay:   int  = 60

    @classmethod
    def from_dict(cls, raw: Dict[str, Any], mysql_port: int) -> Optional["SshTunnelConfig"]:
        if not raw.get("ssh_host"):
            return None
        return cls(
            ssh_host        = str(raw["ssh_host"]).strip(),
            ssh_port        = int(raw.get("ssh_port", 22)),
            ssh_user        = str(raw["ssh_user"]).strip() if raw.get("ssh_user") else None,
            ssh_key         = str(raw["ssh_key"]).strip()  if raw.get("ssh_key")  else None,
            ssh_password    = str(raw["ssh_password"])     if raw.get("ssh_password") else None,
            ssh_remote_host = str(raw.get("ssh_remote_host", "127.0.0.1")).strip(),
            ssh_remote_port = int(raw.get("ssh_remote_port", mysql_port)),
            ssh_local_port  = int(raw["ssh_local_port"]) if raw.get("ssh_local_port") else int(raw.get("port", 13306)),
            ssh_keepalive   = int(raw.get("ssh_keepalive", 30)),
            ssh_retry_delay = int(raw.get("ssh_retry_delay", 5)),
            ssh_max_delay   = int(raw.get("ssh_max_delay", 60)),
        )

    def validate(self, conn_name: str) -> None:
        if not shutil.which("ssh"):
            raise RuntimeError(
                f"Connection '{conn_name}' requires SSH tunnelling but 'ssh' "
                "is not found in PATH. Install OpenSSH client."
            )
        if self.ssh_key and not os.path.isfile(self.ssh_key):
            raise RuntimeError(
                f"Connection '{conn_name}': ssh_key file not found: {self.ssh_key}"
            )
        if not self.ssh_user:
            log.warning(
                "Connection '%s': ssh_user not set — SSH will use system default user.",
                conn_name,
            )


class SshTunnel:
    """
    Manages one SSH port-forward tunnel for one MySQL connection.

    Lifecycle:
      start()  → spawns SSH, waits for port to open, enters reconnect loop
      stop()   → terminates SSH process cleanly
      state    → TunnelState enum value
      status() → dict for mysql_server_status tool
    """

    # How long to wait for the local port to open after SSH starts (seconds)
    _PORT_READY_TIMEOUT = 15
    # How often to poll while waiting for the port
    _PORT_POLL_INTERVAL = 0.25

    def __init__(self, conn_name: str, cfg: SshTunnelConfig) -> None:
        self.conn_name  = conn_name
        self.cfg        = cfg
        self.state      = TunnelState.STOPPED
        self._process:  Optional[asyncio.subprocess.Process] = None
        self._task:     Optional[asyncio.Task] = None
        self._stop_evt  = asyncio.Event()
        self.connect_count   = 0
        self.last_connected: Optional[float] = None
        self.last_error:     Optional[str]   = None

    # ── Public API ─────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the tunnel and block until the port is open (or raise on timeout)."""
        self._stop_evt.clear()
        self.state = TunnelState.CONNECTING
        # First connection attempt is synchronous so startup fails fast
        await self._launch_and_wait()
        # Background task handles reconnection from here on
        self._task = asyncio.create_task(
            self._reconnect_loop(), name=f"ssh-tunnel-{self.conn_name}"
        )

    async def stop(self) -> None:
        """Gracefully stop the tunnel and terminate the SSH process."""
        self._stop_evt.set()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._kill_process()
        self.state = TunnelState.STOPPED
        log.info("SSH tunnel stopped for '%s'", self.conn_name)

    def status(self) -> Dict[str, Any]:
        return {
            "state":          self.state.value,
            "local_port":     self.cfg.ssh_local_port,
            "remote":         f"{self.cfg.ssh_host}:{self.cfg.ssh_remote_host}:{self.cfg.ssh_remote_port}",
            "connect_count":  self.connect_count,
            "last_connected": datetime.fromtimestamp(self.last_connected).isoformat()
                              if self.last_connected else None,
            "last_error":     self.last_error,
        }

    # ── Internal ───────────────────────────────────────────────────────────

    def _build_ssh_cmd(self) -> List[str]:
        cfg = self.cfg
        cmd = [
            "ssh",
            "-N",                        # don't execute a remote command
            "-T",                        # disable pseudo-TTY allocation
            "-o", "ExitOnForwardFailure=yes",   # die if port-forward fails
            "-o", f"ServerAliveInterval={cfg.ssh_keepalive}",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",  # auto-accept new host keys
            "-o", "BatchMode=yes",       # never prompt for passwords
            "-o", "ConnectTimeout=10",
            "-p", str(cfg.ssh_port),
            # Local port forward:  local_port → remote_host:remote_port
            "-L", f"127.0.0.1:{cfg.ssh_local_port}:{cfg.ssh_remote_host}:{cfg.ssh_remote_port}",
        ]
        if cfg.ssh_key:
            cmd += ["-i", cfg.ssh_key, "-o", "IdentitiesOnly=yes"]
        if cfg.ssh_user:
            cmd += [f"{cfg.ssh_user}@{cfg.ssh_host}"]
        else:
            cmd += [cfg.ssh_host]
        return cmd

    async def _spawn(self) -> asyncio.subprocess.Process:
        cmd = self._build_ssh_cmd()
        log.debug("SSH cmd for '%s': %s", self.conn_name, " ".join(cmd))
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            # New process group so we can kill it cleanly
            start_new_session=True,
        )
        return proc

    async def _wait_for_port(self) -> bool:
        """Poll until 127.0.0.1:local_port accepts a TCP connection."""
        deadline = time.monotonic() + self._PORT_READY_TIMEOUT
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.cfg.ssh_local_port),
                    timeout=1.0,
                )
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                await asyncio.sleep(self._PORT_POLL_INTERVAL)
        return False

    async def _launch_and_wait(self) -> None:
        """Spawn SSH and wait for local port to open. Raises on failure."""
        await self._kill_process()
        log.info(
            "SSH tunnel '%s': connecting to %s:%d → 127.0.0.1:%d",
            self.conn_name, self.cfg.ssh_host, self.cfg.ssh_remote_port,
            self.cfg.ssh_local_port,
        )
        try:
            proc = await self._spawn()
        except FileNotFoundError:
            raise RuntimeError("'ssh' executable not found in PATH.")

        self._process = proc

        # Wait for port OR for SSH to die, whichever comes first
        port_task    = asyncio.create_task(self._wait_for_port())
        process_task = asyncio.create_task(proc.wait())

        done, pending = await asyncio.wait(
            {port_task, process_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()

        if process_task in done:
            # SSH exited before port opened
            stderr_bytes = b""
            if proc.stderr:
                try:
                    stderr_bytes = await asyncio.wait_for(proc.stderr.read(2048), timeout=2)
                except Exception:
                    pass
            err_msg = stderr_bytes.decode(errors="replace").strip() or "(no stderr)"
            self.last_error = err_msg
            raise RuntimeError(
                f"SSH tunnel for '{self.conn_name}' exited before port was ready "
                f"(exit code {proc.returncode}): {err_msg}"
            )

        if not port_task.result():
            await self._kill_process()
            raise RuntimeError(
                f"SSH tunnel for '{self.conn_name}' started but port "
                f"127.0.0.1:{self.cfg.ssh_local_port} did not open within "
                f"{self._PORT_READY_TIMEOUT}s."
            )

        self.state = TunnelState.CONNECTED
        self.connect_count += 1
        self.last_connected = time.monotonic()
        self.last_error = None
        log.info(
            "SSH tunnel '%s' ready on 127.0.0.1:%d (connect #%d)",
            self.conn_name, self.cfg.ssh_local_port, self.connect_count,
        )

    async def _reconnect_loop(self) -> None:
        """
        Runs in background. Monitors the SSH process and reconnects with
        exponential backoff when it dies — until stop() is called.
        """
        delay = self.cfg.ssh_retry_delay
        while not self._stop_evt.is_set():
            # Wait for the current process to exit (or stop event)
            if self._process and self._process.returncode is None:
                wait_task  = asyncio.create_task(self._process.wait())
                stop_task  = asyncio.create_task(self._stop_evt.wait())
                done, _    = await asyncio.wait(
                    {wait_task, stop_task}, return_when=asyncio.FIRST_COMPLETED
                )
                wait_task.cancel()
                stop_task.cancel()
                if self._stop_evt.is_set():
                    return

            if self._stop_evt.is_set():
                return

            # SSH process died unexpectedly
            exit_code = self._process.returncode if self._process else "?"
            log.warning(
                "SSH tunnel '%s' died (exit %s). Reconnecting in %ds…",
                self.conn_name, exit_code, delay,
            )
            self.state = TunnelState.RECONNECTING

            # Read stderr for diagnostics
            if self._process and self._process.stderr:
                try:
                    err = await asyncio.wait_for(self._process.stderr.read(2048), timeout=1)
                    if err:
                        self.last_error = err.decode(errors="replace").strip()
                        log.warning("SSH stderr for '%s': %s", self.conn_name, self.last_error)
                except Exception:
                    pass

            # Wait with exponential backoff, but respect stop event
            try:
                await asyncio.wait_for(self._stop_evt.wait(), timeout=delay)
                return   # stop was requested during the wait
            except asyncio.TimeoutError:
                pass     # normal — continue to reconnect

            if self._stop_evt.is_set():
                return

            try:
                await self._launch_and_wait()
                delay = self.cfg.ssh_retry_delay  # reset on success
            except Exception as exc:
                self.last_error = str(exc)
                log.error(
                    "SSH tunnel '%s' reconnect failed: %s. Retrying in %ds.",
                    self.conn_name, exc, delay,
                )
                delay = min(delay * 2, self.cfg.ssh_max_delay)

    async def _kill_process(self) -> None:
        proc = self._process
        if proc is None or proc.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            try:
                proc.terminate()
            except Exception:
                pass
        try:
            await asyncio.wait_for(proc.wait(), timeout=3)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._process = None


# ══════════════════════════════════════════════════════════════════════════════
# Instance config (MySQL + optional SSH tunnel)
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class InstanceConfig:
    name:          str
    label:         str
    host:          str
    port:          int
    user:          str
    password:      str
    database:      Optional[str]
    use_tls:       bool
    ssl_ca:        Optional[str]
    ssl_cert:      Optional[str]
    ssl_key:       Optional[str]
    allow_writes:  bool
    allowed_dbs:   List[str]
    max_rows:      int
    query_timeout: int
    rate_limit:    int
    tunnel_cfg:    Optional[SshTunnelConfig]    = field(default=None, repr=False)
    tunnel:        Optional[SshTunnel]          = field(default=None, repr=False)
    pool:          Optional[aiomysql.Pool]      = field(default=None, repr=False)
    _rate_window:  Dict[str, List[float]]       = field(
                       default_factory=lambda: defaultdict(list), repr=False)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "InstanceConfig":
        for key in ("name", "host", "user", "password"):
            if not raw.get(key):
                raise ValueError(f"Connection object is missing required field: '{key}'")
        name = str(raw["name"]).strip().lower()
        if not _SAFE_IDENTIFIER.match(name):
            raise ValueError(
                f"Connection name '{name}' is invalid. "
                "Use only letters, digits, underscores, or hyphens."
            )
        allowed_dbs = [str(d).strip() for d in raw.get("allowed_dbs", []) if str(d).strip()]
        mysql_port  = int(raw.get("port", 3306))
        tunnel_cfg  = SshTunnelConfig.from_dict(raw, mysql_port)

        cfg = cls(
            name          = name,
            label         = str(raw.get("label", name)).strip() or name,
            host          = str(raw["host"]).strip(),
            port          = mysql_port,
            user          = str(raw["user"]).strip(),
            password      = str(raw["password"]),
            database      = str(raw["database"]).strip() if raw.get("database") else None,
            use_tls       = bool(raw.get("use_tls", False)),
            ssl_ca        = str(raw["ssl_ca"]).strip()   if raw.get("ssl_ca")   else None,
            ssl_cert      = str(raw["ssl_cert"]).strip() if raw.get("ssl_cert") else None,
            ssl_key       = str(raw["ssl_key"]).strip()  if raw.get("ssl_key")  else None,
            allow_writes  = bool(raw.get("allow_writes", False)),
            allowed_dbs   = allowed_dbs,
            max_rows      = int(raw.get("max_rows",      500)),
            query_timeout = int(raw.get("query_timeout", 30)),
            rate_limit    = int(raw.get("rate_limit",    120)),
            tunnel_cfg    = tunnel_cfg,
        )
        if cfg.use_tls and not cfg.ssl_ca:
            log.warning("Connection '%s': use_tls=true but ssl_ca not set — cert NOT verified!", name)
        if tunnel_cfg:
            tunnel_cfg.validate(name)
            cfg.tunnel = SshTunnel(name, tunnel_cfg)
        return cfg

    def check_rate_limit(self) -> Optional[str]:
        now = time.monotonic()
        self._rate_window["q"] = [t for t in self._rate_window["q"] if now - t < 60]
        if len(self._rate_window["q"]) >= self.rate_limit:
            return f"Rate limit exceeded for '{self.name}' ({self.rate_limit} req/min)."
        self._rate_window["q"].append(now)
        return None

    def summary(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "name":              self.name,
            "label":             self.label,
            "host":              self.host,
            "port":              self.port,
            "default_database":  self.database,
            "tls_enforced":      self.use_tls,
            "writes_allowed":    self.allow_writes,
            "allowed_databases": self.allowed_dbs or "all",
            "max_rows":          self.max_rows,
            "query_timeout_s":   self.query_timeout,
        }
        if self.tunnel:
            d["tunnel"] = self.tunnel.status()
        return d


# ── Registry ───────────────────────────────────────────────────────────────
_instances: Dict[str, InstanceConfig] = {}


def _load_instances() -> None:
    raw_env = os.environ.get("MYSQL_CONNECTIONS", "").strip()
    if not raw_env:
        log.critical(
            "MYSQL_CONNECTIONS is not set.\n"
            "Set it to a JSON array, e.g.:\n"
            '  MYSQL_CONNECTIONS=\'[{"name":"app","host":"127.0.0.1","port":13306,'
            '"user":"u","password":"p"}]\''
        )
        sys.exit(1)
    try:
        connections = json.loads(raw_env)
    except json.JSONDecodeError as exc:
        log.critical("MYSQL_CONNECTIONS is not valid JSON: %s", exc)
        sys.exit(1)
    if not isinstance(connections, list) or not connections:
        log.critical("MYSQL_CONNECTIONS must be a non-empty JSON array.")
        sys.exit(1)
    seen: set = set()
    for i, conn in enumerate(connections):
        if not isinstance(conn, dict):
            log.critical("MYSQL_CONNECTIONS[%d] is not a JSON object.", i)
            sys.exit(1)
        try:
            cfg = InstanceConfig.from_dict(conn)
        except (ValueError, RuntimeError) as exc:
            log.critical("MYSQL_CONNECTIONS[%d] error: %s", i, exc)
            sys.exit(1)
        if cfg.name in seen:
            log.critical("Duplicate connection name '%s'.", cfg.name)
            sys.exit(1)
        seen.add(cfg.name)
        _instances[cfg.name] = cfg
        tunnel_info = (
            f"tunnel={cfg.tunnel_cfg.ssh_host}:{cfg.tunnel_cfg.ssh_local_port}"
            if cfg.tunnel_cfg else "no-tunnel"
        )
        log.info(
            "Connection '%s' (%s): mysql=%s:%d db=%s writes=%s %s",
            cfg.name, cfg.label, cfg.host, cfg.port,
            cfg.database or "(none)", cfg.allow_writes, tunnel_info,
        )
    log.info("Loaded %d connection(s): %s", len(_instances), ", ".join(_instances))


def _get_instance(name: str) -> InstanceConfig:
    inst = _instances.get(name.lower())
    if inst is None:
        available = ", ".join(sorted(_instances.keys()))
        raise ValueError(f"Unknown instance '{name}'. Available: {available}")
    return inst


# ── Connection pool ────────────────────────────────────────────────────────
async def _ensure_pool(cfg: InstanceConfig) -> aiomysql.Pool:
    if cfg.pool is not None and not cfg.pool.closed:
        return cfg.pool
    ssl_ctx = None
    if cfg.use_tls:
        ssl_ctx = _ssl.create_default_context()
        if cfg.ssl_ca:
            ssl_ctx.load_verify_locations(cafile=cfg.ssl_ca)
        else:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode    = _ssl.CERT_NONE
        if cfg.ssl_cert and cfg.ssl_key:
            ssl_ctx.load_cert_chain(certfile=cfg.ssl_cert, keyfile=cfg.ssl_key)
    cfg.pool = await aiomysql.create_pool(
        host=cfg.host, port=cfg.port, user=cfg.user, password=cfg.password,
        db=cfg.database, ssl=ssl_ctx, connect_timeout=10,
        autocommit=True, minsize=1, maxsize=5, echo=False,
    )
    log.info("MySQL pool ready for '%s' (%s:%d)", cfg.name, cfg.host, cfg.port)
    return cfg.pool


async def _reset_pool(cfg: InstanceConfig) -> None:
    """Close and discard the pool so it gets rebuilt on next query (post-reconnect)."""
    if cfg.pool and not cfg.pool.closed:
        cfg.pool.close()
        try:
            await asyncio.wait_for(cfg.pool.wait_closed(), timeout=5)
        except asyncio.TimeoutError:
            pass
    cfg.pool = None


@asynccontextmanager
async def _cursor(cfg: InstanceConfig, database: Optional[str] = None):
    if database:
        if not _SAFE_IDENTIFIER.match(database):
            raise ValueError(f"Invalid database name: '{database}'")
        if cfg.allowed_dbs and database not in cfg.allowed_dbs:
            raise PermissionError(
                f"Database '{database}' is not allowed on '{cfg.name}'. "
                f"Allowed: {', '.join(cfg.allowed_dbs)}"
            )
    pool = await _ensure_pool(cfg)
    async with pool.acquire() as conn:
        if database:
            await conn.select_db(database)
        async with conn.cursor(aiomysql.DictCursor) as cur:
            yield cur


# ── Core query executor ────────────────────────────────────────────────────
async def _run_query(cfg: InstanceConfig, sql: str,
                     database: Optional[str], row_limit: Optional[int]) -> Dict[str, Any]:
    if err := cfg.check_rate_limit():
        raise PermissionError(err)
    classification, err = _classify_query(sql, cfg.allow_writes)
    if err:
        raise PermissionError(f"Query rejected: {err}")

    # If this connection uses a tunnel, check it is up
    if cfg.tunnel and cfg.tunnel.state != TunnelState.CONNECTED:
        raise RuntimeError(
            f"SSH tunnel for '{cfg.name}' is {cfg.tunnel.state.value}. "
            "Reconnection is in progress — please try again shortly."
        )

    effective_limit = min(row_limit or cfg.max_rows, cfg.max_rows)
    t0 = time.monotonic()
    try:
        async with _cursor(cfg, database) as cur:
            await asyncio.wait_for(cur.execute(sql), timeout=cfg.query_timeout)
            if cur.description:
                columns  = [d[0] for d in cur.description]
                rows     = await cur.fetchmany(effective_limit)
                has_more = (cur.rowcount or 0) > effective_limit \
                           if cur.rowcount and cur.rowcount != -1 else None
            else:
                columns, rows, has_more = [], [], False
    except asyncio.TimeoutError:
        raise TimeoutError(f"Query on '{cfg.name}' exceeded {cfg.query_timeout}s timeout.")
    except (PermissionError, ValueError, RuntimeError):
        raise
    except aiomysql.OperationalError as exc:
        code, msg = exc.args if len(exc.args) == 2 else (0, str(exc))
        # Pool may be stale after tunnel reconnect — drop it so it rebuilds
        if code in (2003, 2006, 2013):
            log.warning("Lost MySQL connection on '%s' — resetting pool.", cfg.name)
            await _reset_pool(cfg)
        log.warning("OperationalError [%s] %s: %s", cfg.name, code, msg)
        raise RuntimeError(f"DB error on '{cfg.name}' ({code}): {msg}")
    except aiomysql.ProgrammingError as exc:
        code, msg = exc.args if len(exc.args) == 2 else (0, str(exc))
        raise ValueError(f"SQL error on '{cfg.name}' ({code}): {msg}")
    except Exception:
        log.exception("Unexpected error on '%s'", cfg.name)
        raise RuntimeError(f"Unexpected error on '{cfg.name}' — check server logs.")

    duration_ms = round((time.monotonic() - t0) * 1000, 1)
    log.info("Query OK | instance=%s class=%s db=%s rows=%d %sms",
             cfg.name, classification,
             database or cfg.database or "(default)", len(rows), duration_ms)
    return {
        "instance":          cfg.name,
        "classification":    classification,
        "columns":           columns,
        "rows":              [dict(r) for r in rows],
        "row_count":         len(rows),
        "truncated":         has_more,
        "row_limit_applied": effective_limit,
        "duration_ms":       duration_ms,
    }


# ── Pydantic input models ──────────────────────────────────────────────────
_INST_FIELD = Field(
    ...,
    description="Connection name. Call mysql_list_instances to see available names.",
    min_length=1, max_length=64,
)

def _safe_id(v: Optional[str]) -> Optional[str]:
    if v and not _SAFE_IDENTIFIER.match(v):
        raise ValueError("Identifier may only contain letters, digits, underscores, hyphens.")
    return v


class QueryInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    instance: str            = _INST_FIELD
    sql:      str            = Field(..., description="SQL to execute.", min_length=1, max_length=10_000)
    database: Optional[str] = Field(default=None, description="Override default schema.", max_length=64)
    limit:    Optional[int] = Field(default=None, description="Cap rows returned.", ge=1, le=10_000)

    @field_validator("sql")
    @classmethod
    def no_null_bytes(cls, v: str) -> str:
        if "\x00" in v: raise ValueError("Null bytes not allowed in SQL.")
        return v

    @field_validator("instance", "database")
    @classmethod
    def safe_id(cls, v: Optional[str]) -> Optional[str]: return _safe_id(v)


class TableInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    instance: str            = _INST_FIELD
    table:    str            = Field(..., description="Table name.", min_length=1, max_length=64)
    database: Optional[str] = Field(default=None, description="Database name.", max_length=64)

    @field_validator("instance", "table", "database")
    @classmethod
    def safe_id(cls, v: Optional[str]) -> Optional[str]: return _safe_id(v)


class InstanceOnlyInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    instance: str            = _INST_FIELD
    database: Optional[str] = Field(default=None, description="Database name.", max_length=64)

    @field_validator("instance", "database")
    @classmethod
    def safe_id(cls, v: Optional[str]) -> Optional[str]: return _safe_id(v)


# ── Lifespan ───────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan():
    _load_instances()

    # 1. Start all SSH tunnels first (blocking until each port is open)
    tunnel_instances = [cfg for cfg in _instances.values() if cfg.tunnel]
    if tunnel_instances:
        log.info("Starting %d SSH tunnel(s)…", len(tunnel_instances))
        for cfg in tunnel_instances:
            try:
                await cfg.tunnel.start()
            except Exception as exc:
                log.critical("Failed to establish SSH tunnel for '%s': %s", cfg.name, exc)
                sys.exit(1)

    # 2. Open MySQL connection pools
    log.info("Connecting MySQL pools for %d instance(s)…", len(_instances))
    failed = []
    for name, cfg in _instances.items():
        try:
            await _ensure_pool(cfg)
            log.info("  ✓  '%s' ready", name)
        except Exception as exc:
            log.error("  ✗  '%s' pool failed: %s", name, exc)
            failed.append(name)
    if failed:
        log.critical("Cannot open MySQL pool for: %s — fix config and restart.", ", ".join(failed))
        sys.exit(1)

    log.info("All connections ready ✓")
    yield

    # Shutdown: close pools then tunnels
    for name, cfg in _instances.items():
        if cfg.pool and not cfg.pool.closed:
            cfg.pool.close()
            await cfg.pool.wait_closed()
            log.info("MySQL pool closed for '%s'", name)
        if cfg.tunnel:
            await cfg.tunnel.stop()


mcp = FastMCP("mysql_mcp", lifespan=lifespan)


# ── Tools ──────────────────────────────────────────────────────────────────

@mcp.tool(name="mysql_list_instances", annotations={
    "title": "List MySQL Connections", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_list_instances() -> str:
    """List all configured MySQL connections with labels, settings, and tunnel state.

    Always call this first to discover available connection names.

    Returns:
        str: JSON with { instances: [{ name, label, host, port,
             default_database, tls_enforced, writes_allowed,
             allowed_databases, max_rows, query_timeout_s,
             tunnel?: { state, local_port, remote, connect_count,
                        last_connected, last_error } }], count }
    """
    return _to_json({"instances": [c.summary() for c in _instances.values()],
                     "count": len(_instances)})


@mcp.tool(name="mysql_query", annotations={
    "title": "Execute SQL Query", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_query(params: QueryInput) -> str:
    """Execute a SQL statement on a named MySQL connection.

    If the connection uses an SSH tunnel and the tunnel is currently
    reconnecting, returns an error with the tunnel state — retry shortly.

    Args:
        params (QueryInput):
            - instance (str): Connection name (from mysql_list_instances)
            - sql (str): SQL statement (max 10,000 chars)
            - database (Optional[str]): Override default schema
            - limit (Optional[int]): Max rows (capped by connection setting)

    Returns:
        str: JSON with { instance, classification, columns, rows,
             row_count, truncated, row_limit_applied, duration_ms }
    """
    try:
        return _to_json(await _run_query(
            _get_instance(params.instance), params.sql, params.database, params.limit))
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


@mcp.tool(name="mysql_list_databases", annotations={
    "title": "List Databases", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_list_databases(params: InstanceOnlyInput) -> str:
    """List all databases visible on a given connection (filtered to allowed_dbs if set).

    Args:
        params (InstanceOnlyInput): instance (str)

    Returns:
        str: JSON with { instance, databases: [...], count }
    """
    try:
        cfg = _get_instance(params.instance)
        result = await _run_query(cfg, "SHOW DATABASES", None, 1000)
        dbs = [list(r.values())[0] for r in result["rows"]]
        if cfg.allowed_dbs:
            dbs = [d for d in dbs if d in cfg.allowed_dbs]
        return _to_json({"instance": cfg.name, "databases": dbs, "count": len(dbs)})
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


@mcp.tool(name="mysql_list_tables", annotations={
    "title": "List Tables", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_list_tables(params: InstanceOnlyInput) -> str:
    """List all tables and views in a database on a given connection.

    Args:
        params (InstanceOnlyInput): instance (str), database (Optional[str])

    Returns:
        str: JSON with { instance, database, tables: [{name, type}], count }
    """
    try:
        cfg = _get_instance(params.instance)
        result = await _run_query(cfg, "SHOW FULL TABLES", params.database, 2000)
        tables = [{"name": list(r.values())[0],
                   "type": list(r.values())[1] if len(r) > 1 else "BASE TABLE"}
                  for r in result["rows"]]
        return _to_json({"instance": cfg.name,
                         "database": params.database or cfg.database or "(default)",
                         "tables": tables, "count": len(tables)})
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


@mcp.tool(name="mysql_describe_table", annotations={
    "title": "Describe Table Schema", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_describe_table(params: TableInput) -> str:
    """Return full schema for a table: columns, indexes, CREATE DDL.

    Args:
        params (TableInput): instance (str), table (str), database (Optional[str])

    Returns:
        str: JSON with { instance, table, database, columns, indexes, create_statement }
    """
    try:
        cfg = _get_instance(params.instance)
        t   = f"`{params.table}`"
        cols = await _run_query(cfg, f"DESCRIBE {t}",          params.database, 500)
        idxs = await _run_query(cfg, f"SHOW INDEX FROM {t}",   params.database, 500)
        ddl  = await _run_query(cfg, f"SHOW CREATE TABLE {t}", params.database,   1)
        vals = list(ddl["rows"][0].values()) if ddl["rows"] else []
        create_stmt = vals[1] if len(vals) > 1 else (vals[0] if vals else "")
        return _to_json({"instance": cfg.name, "table": params.table,
                         "database": params.database or cfg.database or "(default)",
                         "columns": cols["rows"], "indexes": idxs["rows"],
                         "create_statement": create_stmt})
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


@mcp.tool(name="mysql_explain_query", annotations={
    "title": "Explain Query Execution Plan", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": True, "openWorldHint": False,
})
async def mysql_explain_query(params: QueryInput) -> str:
    """EXPLAIN a SELECT statement on a given connection.

    Args:
        params (QueryInput): instance (str), sql (str), database (Optional[str])

    Returns:
        str: JSON with { instance, explain_rows, warnings, duration_ms }
    """
    if not re.match(r"^\s*SELECT\b", params.sql.strip(), re.IGNORECASE):
        return _to_json({"error": "Only SELECT statements accepted.", "instance": params.instance})
    try:
        cfg     = _get_instance(params.instance)
        explain = await _run_query(cfg, f"EXPLAIN {params.sql}", params.database, 100)
        warns   = await _run_query(cfg, "SHOW WARNINGS",         params.database,  50)
        return _to_json({"instance": cfg.name, "explain_rows": explain["rows"],
                         "warnings": warns["rows"], "duration_ms": explain["duration_ms"]})
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


@mcp.tool(name="mysql_server_status", annotations={
    "title": "MySQL Connection Status", "readOnlyHint": True,
    "destructiveHint": False, "idempotentHint": False, "openWorldHint": False,
})
async def mysql_server_status(params: InstanceOnlyInput) -> str:
    """Return version, uptime, connections, TLS status, and tunnel state.

    Args:
        params (InstanceOnlyInput): instance (str)

    Returns:
        str: JSON with { instance, label, version, uptime_seconds,
             connections, tls_cipher, tls_enabled, config,
             tunnel?: { state, connect_count, last_connected, last_error } }
    """
    try:
        cfg    = _get_instance(params.instance)
        ver    = await _run_query(cfg, "SELECT VERSION() AS version", None, 1)
        status = await _run_query(
            cfg,
            "SHOW STATUS WHERE Variable_name IN "
            "('Uptime','Threads_connected','Max_used_connections','Ssl_cipher')",
            None, 20,
        )
        smap = {r["Variable_name"]: r["Value"] for r in status["rows"]}
        result: Dict[str, Any] = {
            "instance":       cfg.name,
            "label":          cfg.label,
            "version":        ver["rows"][0]["version"] if ver["rows"] else "unknown",
            "uptime_seconds": int(smap.get("Uptime", 0)),
            "connections":    {"current":  int(smap.get("Threads_connected",    0)),
                               "max_used": int(smap.get("Max_used_connections", 0))},
            "tls_cipher":     smap.get("Ssl_cipher") or None,
            "tls_enabled":    bool(smap.get("Ssl_cipher")),
            "config":         cfg.summary(),
        }
        if cfg.tunnel:
            result["tunnel"] = cfg.tunnel.status()
        return _to_json(result)
    except Exception as exc:
        return _to_json({"error": str(exc), "instance": params.instance})


# ── Entry point ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    mcp.run()
