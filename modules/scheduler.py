"""
modules/scheduler.py — Scheduled attack and scan automation.
Persistent schedule stored in JSON (~/.darkcracker/schedule.json).
Background QTimer checks for due tasks every 60 seconds.
"""
from core.worker import BaseWorker
import importlib
import json
import uuid
from datetime import datetime, timedelta
from typing import Optional


from core.config import CONFIG_DIR

# ── Storage path ──────────────────────────────────────────────────────────────
_SCHEDULE_FILE = CONFIG_DIR / "schedule.json"
_DATE_FMT      = "%Y-%m-%dT%H:%M:%S"

# ── Valid task types ──────────────────────────────────────────────────────────
TASK_TYPES = ["wifi_scan", "network_scan", "port_scan", "report"]


# ── ScheduledTask dataclass ───────────────────────────────────────────────────

class ScheduledTask:
    """
    Represents a single scheduled task.

    Attributes:
        id              — UUID string
        name            — Human-readable task name
        task_type       — One of TASK_TYPES
        config          — Arbitrary config dict (target, interface, etc.)
        interval_minutes— Repeat interval in minutes
        next_run        — datetime of next scheduled execution
        last_run        — datetime of last execution, or None
        enabled         — Whether the task is active
        run_count       — Total completed executions
    """

    def __init__(
        self,
        name:             str,
        task_type:        str,
        config:           dict,
        interval_minutes: int,
        next_run:         Optional[datetime] = None,
        last_run:         Optional[datetime] = None,
        enabled:          bool = True,
        run_count:        int  = 0,
        task_id:          Optional[str] = None,
    ):
        self.id               = task_id or str(uuid.uuid4())
        self.name             = name
        self.task_type        = task_type
        self.config           = config
        self.interval_minutes = interval_minutes
        self.next_run         = next_run or datetime.now()
        self.last_run         = last_run
        self.enabled          = enabled
        self.run_count        = run_count

    # ── Serialization ─────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize to a JSON-safe dict."""
        return {
            "id":               self.id,
            "name":             self.name,
            "task_type":        self.task_type,
            "config":           self.config,
            "interval_minutes": self.interval_minutes,
            "next_run":         self.next_run.strftime(_DATE_FMT),
            "last_run":         self.last_run.strftime(_DATE_FMT) if self.last_run else None,
            "enabled":          self.enabled,
            "run_count":        self.run_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ScheduledTask":
        """Deserialize from a dict (as stored in JSON)."""
        last_run_raw = data.get("last_run")
        return cls(
            task_id          = data.get("id"),
            name             = data.get("name", "Unnamed"),
            task_type        = data.get("task_type", "wifi_scan"),
            config           = data.get("config", {}),
            interval_minutes = data.get("interval_minutes", 60),
            next_run         = datetime.strptime(data["next_run"], _DATE_FMT)
                               if data.get("next_run") else datetime.now(),
            last_run         = datetime.strptime(last_run_raw, _DATE_FMT)
                               if last_run_raw else None,
            enabled          = data.get("enabled", True),
            run_count        = data.get("run_count", 0),
        )

    def __repr__(self) -> str:
        return f"<ScheduledTask id={self.id[:8]} name={self.name!r} type={self.task_type}>"


# ── Task execution worker ─────────────────────────────────────────────────────

class _TaskWorker(BaseWorker):
    """Executes a single scheduled task in a background thread."""

    def __init__(self, task: ScheduledTask, on_finished=None, on_failed=None):
        super().__init__()
        self._task       = task
        self._on_finished = on_finished
        self._on_failed   = on_failed

    def run(self):
        task = self._task
        try:
            result = self._dispatch(task)
            self._call(self._on_finished, task.id, result or {})
        except Exception as exc:
            self._call(self._on_failed, task.id, str(exc))

    def _dispatch(self, task: ScheduledTask) -> dict:
        """Dispatch execution based on task_type."""
        t  = task.task_type
        cfg = task.config

        if t == "wifi_scan":
            return self._run_wifi_scan(cfg)
        elif t == "network_scan":
            return self._run_network_scan(cfg)
        elif t == "port_scan":
            return self._run_port_scan(cfg)
        elif t == "report":
            return self._run_report(cfg)
        else:
            raise ValueError(f"Unknown task type: {t}")

    # ── Dispatch implementations ──────────────────────────────────────────

    def _run_wifi_scan(self, cfg: dict) -> dict:
        """Trigger a WiFi scan via the wifi_scanner module."""
        try:
            wifi_mod = importlib.import_module("modules.wifi_scanner")
            iface    = cfg.get("interface", "wlan0")
            scanner  = wifi_mod.WifiScanner()
            # WifiScanner.scan() is synchronous in subprocess-based impls
            scanner.scan(iface)
            return {"status": "ok", "task": "wifi_scan", "interface": iface}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _run_network_scan(self, cfg: dict) -> dict:
        """Trigger a network scan via network_discovery module."""
        try:
            nd_mod  = importlib.import_module("modules.network_discovery")
            target  = cfg.get("target", "192.168.1.0/24")
            scanner = nd_mod.NetworkDiscovery()
            scanner.scan(target)
            return {"status": "ok", "task": "network_scan", "target": target}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _run_port_scan(self, cfg: dict) -> dict:
        """Trigger a port scan via port_scanner module."""
        try:
            ps_mod  = importlib.import_module("modules.port_scanner")
            target  = cfg.get("target", "")
            ports   = cfg.get("ports", "1-1024")
            scanner = ps_mod.PortScanner()
            scanner.scan(target, ports)
            return {"status": "ok", "task": "port_scan", "target": target}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _run_report(self, cfg: dict) -> dict:
        """Generate a report via report_generator module."""
        try:
            rg_mod    = importlib.import_module("modules.report_generator")
            fmt       = cfg.get("format", "HTML")
            generator = rg_mod.ReportGenerator()
            path      = generator.generate(fmt)
            return {"status": "ok", "task": "report", "path": str(path)}
        except Exception as exc:
            return {"status": "error", "error": str(exc)}


# ── Scheduler singleton ───────────────────────────────────────────────────────

_scheduler_instance: Optional["Scheduler"] = None


class Scheduler:
    """
    Cron-style attack and scan scheduler.

    Persists tasks to ~/.darkcracker/schedule.json.
    A background daemon thread fires every 60s to check for due tasks.

    Callbacks:
        on_task_started(task_id, task_name)
        on_task_completed(task_id, result_dict)
        on_task_failed(task_id, error_message)
        on_schedule_updated()
    """

    def __init__(self, on_task_started=None, on_task_completed=None,
                 on_task_failed=None, on_schedule_updated=None):
        import threading as _threading
        self._tasks: dict[str, ScheduledTask] = {}
        self._workers: dict[str, _TaskWorker] = {}
        self._on_task_started      = on_task_started
        self._on_task_completed    = on_task_completed
        self._on_task_failed       = on_task_failed
        self._on_schedule_updated  = on_schedule_updated
        self._stop_event           = _threading.Event()

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        self._load()

        # Background check thread (daemon — exits with main process)
        self._timer_thread = _threading.Thread(
            target=self._timer_loop, daemon=True
        )
        self._timer_thread.start()

    # ── Public API ────────────────────────────────────────────────────────────

    def add_task(
        self,
        name:             str,
        task_type:        str,
        config:           dict,
        interval_minutes: int,
    ) -> str:
        """
        Create and persist a new scheduled task.
        Returns the new task's UUID string.
        """
        task = ScheduledTask(
            name             = name,
            task_type        = task_type,
            config           = config,
            interval_minutes = interval_minutes,
            next_run         = datetime.now() + timedelta(minutes=interval_minutes),
        )
        self._tasks[task.id] = task
        self._save()
        self._safe_emit("schedule_updated", )
        return task.id

    def remove_task(self, task_id: str):
        """Remove a task by ID."""
        if task_id in self._tasks:
            del self._tasks[task_id]
            self._save()
            self._safe_emit("schedule_updated", )

    def enable_task(self, task_id: str):
        """Enable a previously disabled task."""
        if task_id in self._tasks:
            self._tasks[task_id].enabled = True
            self._save()
            self._safe_emit("schedule_updated", )

    def disable_task(self, task_id: str):
        """Disable a task (keeps it in schedule but skips execution)."""
        if task_id in self._tasks:
            self._tasks[task_id].enabled = False
            self._save()
            self._safe_emit("schedule_updated", )

    def get_tasks(self) -> list:
        """Return all tasks as a list of ScheduledTask objects."""
        return list(self._tasks.values())

    def run_now(self, task_id: str):
        """Force immediate execution of a task regardless of next_run."""
        task = self._tasks.get(task_id)
        if task:
            self._execute_task(task)

    def _safe_emit(self, sig, *a):
        _cb = {
            "task_started":     self._on_task_started,
            "task_completed":   self._on_task_completed,
            "task_failed":      self._on_task_failed,
            "schedule_updated": self._on_schedule_updated,
        }.get(sig)
        if _cb:
            try:
                _cb(*a)
            except Exception:
                pass

    # ── Background timer loop ─────────────────────────────────────────────────

    def _timer_loop(self):
        """Runs in a daemon thread; fires _check_due every 60 seconds."""
        while not self._stop_event.wait(60):
            self._check_due()

    def stop(self):
        """Signal the timer loop to exit."""
        self._stop_event.set()

    # ── Scheduler tick ────────────────────────────────────────────────────────

    def _check_due(self):
        """Find enabled tasks whose next_run has passed and execute them."""
        now = datetime.now()
        for task in list(self._tasks.values()):
            if task.enabled and task.next_run <= now:
                worker = self._workers.get(task.id)
                if worker and worker.is_alive():
                    continue
                self._execute_task(task)

    # ── Task execution ────────────────────────────────────────────────────────

    def _execute_task(self, task: ScheduledTask):
        """Dispatch a task to a background worker thread."""
        task.next_run = datetime.now() + timedelta(minutes=task.interval_minutes)
        self._save()
        self._safe_emit("task_started", task.id, task.name)

        worker = _TaskWorker(
            task,
            on_finished=self._task_finished_cb,
            on_failed=self._task_failed_cb,
        )
        self._workers[task.id] = worker
        worker.start()

    def _task_finished_cb(self, task_id: str, result: dict):
        task = self._tasks.get(task_id)
        if task:
            task.last_run  = datetime.now()
            task.run_count += 1
            self._save()
            self._safe_emit("schedule_updated")
        self._safe_emit("task_completed", task_id, result)
        self._workers.pop(task_id, None)

    def _task_failed_cb(self, task_id: str, error: str):
        task = self._tasks.get(task_id)
        if task:
            task.last_run = datetime.now()
            self._save()
            self._safe_emit("schedule_updated")
        self._safe_emit("task_failed", task_id, error)
        self._workers.pop(task_id, None)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self):
        """Write all tasks to ~/.darkcracker/schedule.json."""
        try:
            data = [t.to_dict() for t in self._tasks.values()]
            _SCHEDULE_FILE.write_text(json.dumps(data, indent=2))
        except Exception:
            pass  # Non-fatal — tasks still live in memory

    def _load(self):
        """Load tasks from ~/.darkcracker/schedule.json if it exists."""
        if not _SCHEDULE_FILE.exists():
            return
        try:
            data = json.loads(_SCHEDULE_FILE.read_text())
            for item in data:
                task = ScheduledTask.from_dict(item)
                self._tasks[task.id] = task
        except Exception:
            pass  # Corrupted file — start fresh


# ── Singleton accessor ────────────────────────────────────────────────────────

def get_scheduler() -> Scheduler:
    """Return (or create) the global Scheduler singleton."""
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = Scheduler()
    return _scheduler_instance
