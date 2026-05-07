"""
core/database.py — SQLite persistence layer for DARK CRACKER OPS.
All session, host, port, credential, and vulnerability data
is stored here.  Uses WAL journal mode for concurrent read access.
"""
import sqlite3
import uuid
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.config import DB_PATH, DISCLAIMER_FILE, ensure_dirs
from core.logger import get_logger

log = get_logger("database")

# ── Schema ────────────────────────────────────────────────────────────────────
SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT    PRIMARY KEY,
    start_time   TEXT,
    end_time     TEXT,
    target_ssid  TEXT,
    target_bssid TEXT,
    channel      INTEGER,
    encryption   TEXT,
    attack_type  TEXT,
    result       TEXT,
    password     TEXT,
    duration     INTEGER,
    hosts_found  INTEGER DEFAULT 0,
    ports_found  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT,
    ip          TEXT,
    mac         TEXT,
    hostname    TEXT,
    vendor      TEXT,
    os_guess    TEXT,
    device_type TEXT,
    risk_score  INTEGER DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS ports (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER,
    port       INTEGER,
    protocol   TEXT,
    state      TEXT,
    service    TEXT,
    version    TEXT,
    risk_level TEXT,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    cred_type  TEXT,
    target     TEXT,
    username   TEXT,
    password   TEXT,
    service    TEXT,
    port       INTEGER,
    timestamp  TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions(id)
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id     INTEGER,
    cve_id      TEXT,
    description TEXT,
    severity    TEXT,
    cvss_score  REAL,
    FOREIGN KEY (host_id) REFERENCES hosts(id)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE INDEX IF NOT EXISTS idx_hosts_session   ON hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_ports_host      ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_creds_session   ON credentials(session_id);
CREATE INDEX IF NOT EXISTS idx_creds_target    ON credentials(target);
CREATE INDEX IF NOT EXISTS idx_vulns_host      ON vulnerabilities(host_id);
"""


class Database:
    """
    Single-instance database wrapper.  Instantiate once and pass around, or
    use as a module-level singleton via ``get_db()``.
    """

    def __init__(self):
        ensure_dirs()
        self._conn = sqlite3.connect(
            str(DB_PATH),
            check_same_thread=False,
            timeout=30,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        log.info("Database initialized: %s", DB_PATH)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self._conn.execute(sql, params)

    def _commit(self) -> None:
        self._conn.commit()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def new_session(
        self,
        ssid: str = "",
        bssid: str = "",
        channel: int = 0,
        encryption: str = "",
        attack_type: str = "Auto",
    ) -> str:
        """Create a new session row and return its 8-char UUID prefix."""
        sid = str(uuid.uuid4())[:8]
        now = datetime.now().isoformat()
        self._execute(
            "INSERT INTO sessions"
            "(id, start_time, target_ssid, target_bssid, channel, encryption, attack_type, result)"
            " VALUES(?,?,?,?,?,?,?,'running')",
            (sid, now, ssid, bssid, channel, encryption, attack_type),
        )
        self._commit()
        log.debug("New session: %s  target=%s", sid, ssid or bssid)
        return sid

    def close_session(
        self,
        sid: str,
        password: str = "",
        result: str = "done",
        hosts: int = 0,
        ports: int = 0,
    ) -> None:
        """Mark a session as finished and record final stats."""
        now = datetime.now().isoformat()
        self._execute(
            "UPDATE sessions"
            " SET end_time=?, result=?, password=?, hosts_found=?, ports_found=?"
            " WHERE id=?",
            (now, result, password, hosts, ports, sid),
        )
        self._commit()
        log.debug("Session closed: %s  result=%s", sid, result)

    def get_session(self, sid: str) -> Optional[Dict]:
        row = self._execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        return dict(row) if row else None

    def get_sessions(self) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM sessions ORDER BY start_time DESC"
        ).fetchall()
        return [dict(r) for r in rows]

    def delete_session(self, sid: str) -> None:
        """Remove a session and all its child records."""
        for table in ("credentials",):
            self._execute(f"DELETE FROM {table} WHERE session_id=?", (sid,))
        host_ids = [
            r[0]
            for r in self._execute(
                "SELECT id FROM hosts WHERE session_id=?", (sid,)
            ).fetchall()
        ]
        for hid in host_ids:
            self._execute("DELETE FROM ports WHERE host_id=?", (hid,))
            self._execute("DELETE FROM vulnerabilities WHERE host_id=?", (hid,))
        self._execute("DELETE FROM hosts WHERE session_id=?", (sid,))
        self._execute("DELETE FROM sessions WHERE id=?", (sid,))
        self._commit()
        log.debug("Session deleted: %s", sid)

    # ── Hosts ─────────────────────────────────────────────────────────────────

    def add_host(self, session_id: str, host: Dict) -> int:
        """Insert a host record and return its auto-increment ID."""
        cur = self._execute(
            "INSERT INTO hosts"
            "(session_id, ip, mac, hostname, vendor, os_guess, device_type, risk_score)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                session_id,
                host.get("ip", ""),
                host.get("mac", ""),
                host.get("hostname", ""),
                host.get("vendor", ""),
                host.get("os_guess", ""),
                host.get("device_type", ""),
                host.get("risk_score", 0),
            ),
        )
        self._commit()
        return cur.lastrowid

    def get_hosts(self, session_id: str) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM hosts WHERE session_id=?", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def update_host_risk(self, host_id: int, risk_score: int) -> None:
        self._execute(
            "UPDATE hosts SET risk_score=? WHERE id=?", (risk_score, host_id)
        )
        self._commit()

    # ── Ports ─────────────────────────────────────────────────────────────────

    def add_port(self, host_id: int, port: Dict) -> None:
        self._execute(
            "INSERT INTO ports"
            "(host_id, port, protocol, state, service, version, risk_level)"
            " VALUES(?,?,?,?,?,?,?)",
            (
                host_id,
                port.get("port", 0),
                port.get("protocol", "tcp"),
                port.get("state", "open"),
                port.get("service", ""),
                port.get("version", ""),
                port.get("risk_level", "LOW"),
            ),
        )
        self._commit()

    def get_ports(self, host_id: int) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM ports WHERE host_id=?", (host_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Credentials ───────────────────────────────────────────────────────────

    def add_credential(
        self,
        session_id: str,
        cred_type: str,
        target: str,
        username: str = "",
        password: str = "",
        service: str = "",
        port: int = 0,
    ) -> None:
        self._execute(
            "INSERT INTO credentials"
            "(session_id, cred_type, target, username, password, service, port, timestamp)"
            " VALUES(?,?,?,?,?,?,?,?)",
            (
                session_id,
                cred_type,
                target,
                username,
                password,
                service,
                port,
                datetime.now().isoformat(),
            ),
        )
        self._commit()
        log.debug("Credential stored: type=%s target=%s user=%s", cred_type, target, username)

    def get_credentials(self, session_id: str) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM credentials WHERE session_id=?", (session_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Vulnerabilities ───────────────────────────────────────────────────────

    def add_vulnerability(
        self,
        host_id: int,
        cve_id: str,
        description: str,
        severity: str,
        cvss_score: float = 0.0,
    ) -> None:
        self._execute(
            "INSERT INTO vulnerabilities"
            "(host_id, cve_id, description, severity, cvss_score)"
            " VALUES(?,?,?,?,?)",
            (host_id, cve_id, description, severity, cvss_score),
        )
        self._commit()

    def get_vulnerabilities(self, host_id: int) -> List[Dict]:
        rows = self._execute(
            "SELECT * FROM vulnerabilities WHERE host_id=?", (host_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Settings ──────────────────────────────────────────────────────────────

    def get_setting(self, key: str, default: Any = None) -> Any:
        row = self._execute(
            "SELECT value FROM settings WHERE key=?", (key,)
        ).fetchone()
        if row is None:
            return default
        try:
            return json.loads(row[0])
        except Exception:
            return row[0]

    def set_setting(self, key: str, value: Any) -> None:
        self._execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES(?,?)",
            (key, json.dumps(value)),
        )
        self._commit()

    def get_all_settings(self) -> Dict[str, Any]:
        rows = self._execute("SELECT key, value FROM settings").fetchall()
        result: Dict[str, Any] = {}
        for row in rows:
            try:
                result[row[0]] = json.loads(row[1])
            except Exception:
                result[row[0]] = row[1]
        return result

    # ── Disclaimer / first-run ────────────────────────────────────────────────

    def is_first_run(self) -> bool:
        """Return True if the user has never accepted the disclaimer."""
        return not DISCLAIMER_FILE.exists()

    def accept_disclaimer(self) -> None:
        """Record that the disclaimer has been accepted."""
        DISCLAIMER_FILE.touch()

    # ── Convenience aliases used by TUI screens ───────────────────────────────

    def get_all_sessions(self) -> List[Dict]:
        """Alias for get_sessions() — returns all sessions newest-first."""
        return self.get_sessions()

    def get_session_hosts(self, session_id: str) -> List[Dict]:
        """Return all hosts discovered in *session_id*."""
        return self.get_hosts(session_id)

    def get_session_creds(self, session_id: str) -> List[Dict]:
        """Return all credentials captured in *session_id*."""
        return self.get_credentials(session_id)

    def get_session_ports(self, session_id: str) -> List[Dict]:
        """Return all open ports across all hosts in *session_id*."""
        rows = self._execute(
            """
            SELECT p.*, h.ip AS host_ip
            FROM ports p
            JOIN hosts h ON p.host_id = h.id
            WHERE h.session_id = ?
            ORDER BY h.ip, p.port
            """,
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_session_vulns(self, session_id: str) -> List[Dict]:
        """Return all vulnerabilities across all hosts in *session_id*."""
        rows = self._execute(
            """
            SELECT v.*, h.ip AS host_ip
            FROM vulnerabilities v
            JOIN hosts h ON v.host_id = h.id
            WHERE h.session_id = ?
            ORDER BY v.cvss_score DESC
            """,
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> Dict[str, int]:
        """Return high-level counts for the dashboard."""
        sessions  = self._execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
        hosts     = self._execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        creds     = self._execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
        cracked   = self._execute(
            "SELECT COUNT(*) FROM sessions WHERE password != '' AND password IS NOT NULL"
        ).fetchone()[0]
        return {
            "sessions":  sessions,
            "hosts":     hosts,
            "creds":     creds,
            "cracked":   cracked,
        }

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        try:
            self._conn.close()
            log.debug("Database connection closed.")
        except Exception:
            pass


# ── Module-level singleton ────────────────────────────────────────────────────
_db_instance: Optional[Database] = None


def get_db() -> Database:
    """Return the shared Database instance, creating it on first call."""
    global _db_instance
    if _db_instance is None:
        _db_instance = Database()
    return _db_instance
