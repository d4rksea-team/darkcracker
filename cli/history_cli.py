"""
cli/history_cli.py — Session history, detail view, PDF/JSON/HTML/TXT report export.
"""
import json
import threading
from typing import Optional

from cli.display import (
    print_section, print_menu, print_table,
    info, success_msg, warn_msg, error_msg, log as cli_log,
    get_input, ask_yn, wait_enter, get_choice, safe_print
)
from cli.colors import cyan, green, red, yellow, dim, gray, bold


# ── List sessions ──────────────────────────────────────────────────────────────

def _list_sessions() -> list:
    """Fetch and display all sessions. Returns the list."""
    try:
        from core.database import get_db
        db       = get_db()
        sessions = db.get_all_sessions()
    except Exception as e:
        error_msg(f"Database error: {e}")
        return []

    if not sessions:
        warn_msg("No sessions recorded yet.")
        return []

    headers = ["#", "ID", "DATE", "SSID", "ATTACK", "RESULT", "DURATION"]
    rows = []
    for i, s in enumerate(sessions, 1):
        result = s.get("result", "")
        rfn    = green if result == "success" else red
        rows.append([
            str(i),
            s.get("id", "")[:12],
            s.get("start_time", "")[:16],
            s.get("target_ssid", ""),
            s.get("attack_type", ""),
            rfn(result.upper()),
            str(s.get("duration", "")),
        ])
    print_table(headers, rows)
    return sessions


# ── View session detail ────────────────────────────────────────────────────────

def _view_session(sessions: list) -> None:
    if not sessions:
        warn_msg("No sessions to display.")
        wait_enter()
        return

    safe_print()
    choice = get_choice(len(sessions), "Select session (0=cancel)")
    if not choice or choice == 0:
        return

    s = sessions[choice - 1]
    sess_id = s.get("id", "")

    try:
        from core.database import get_db
        db    = get_db()
        hosts = db.get_session_hosts(sess_id)
        ports = db.get_session_ports(sess_id)
        vulns = db.get_session_vulns(sess_id)
        creds = db.get_session_creds(sess_id)
    except Exception as e:
        error_msg(f"Database error: {e}")
        wait_enter()
        return

    print_section(f"SESSION: {sess_id[:12]}")
    safe_print(f"  {cyan('Target  :')}  {s.get('target_ssid','?')}  {dim(s.get('target_bssid',''))}")
    safe_print(f"  {cyan('Attack  :')}  {s.get('attack_type','?')}")
    result = s.get("result", "")
    rfn    = green if result == "success" else red
    safe_print(f"  {cyan('Result  :')}  {rfn(result.upper())}")
    safe_print(f"  {cyan('Date    :')}  {s.get('start_time','?')}")
    safe_print(f"  {cyan('Duration:')}  {s.get('duration','?')}")
    if s.get("password"):
        safe_print(f"  {green('PASSWORD:')}  {bold(green(s['password']))}")
    safe_print()

    if hosts:
        safe_print(f"  {cyan(f'HOSTS ({len(hosts)})')}")
        hrows = [[h.get("ip",""), h.get("hostname",""), h.get("vendor",""), h.get("os_guess","")] for h in hosts]
        print_table(["IP", "HOSTNAME", "VENDOR", "OS"], hrows)

    if ports:
        safe_print(f"\n  {cyan(f'PORTS ({len(ports)})')}")
        prows = [[str(p.get("port","")), p.get("protocol",""), p.get("service",""), p.get("version","")] for p in ports]
        print_table(["PORT", "PROTO", "SERVICE", "VERSION"], prows)

    if vulns:
        safe_print(f"\n  {cyan(f'VULNERABILITIES ({len(vulns)})')}")
        vrows = [[v.get("cve_id",""), v.get("severity",""), str(v.get("cvss_score","")), v.get("description","")[:50]] for v in vulns]
        print_table(["CVE", "SEVERITY", "CVSS", "DESCRIPTION"], vrows)

    if creds:
        safe_print(f"\n  {cyan(f'CREDENTIALS ({len(creds)})')}")
        crows = [[c.get("service",""), c.get("username",""), c.get("password",""), c.get("host","")] for c in creds]
        print_table(["SERVICE", "USERNAME", "PASSWORD", "HOST"], crows)

    wait_enter()


# ── Generate report ────────────────────────────────────────────────────────────

_FORMATS = ["PDF", "HTML", "JSON", "TXT"]
_CLASSIFICATIONS = ["TLP:RED", "TLP:AMBER", "TLP:GREEN", "INTERNAL", "PUBLIC"]


def _generate_report(sessions: list) -> None:
    if not sessions:
        warn_msg("No sessions available.")
        wait_enter()
        return

    safe_print()
    choice = get_choice(len(sessions), "Select session for report (0=cancel)")
    if not choice or choice == 0:
        return

    s       = sessions[choice - 1]
    sess_id = s.get("id", "")

    # Format
    print_menu("REPORT FORMAT", _FORMATS)
    fmt_choice = get_choice(len(_FORMATS))
    if not fmt_choice or fmt_choice == 0:
        return
    fmt = _FORMATS[fmt_choice - 1].lower()

    # Classification
    print_menu("CLASSIFICATION", _CLASSIFICATIONS)
    cls_choice = get_choice(len(_CLASSIFICATIONS))
    if not cls_choice or cls_choice == 0:
        cls_choice = 3  # default TLP:GREEN
    classif = _CLASSIFICATIONS[cls_choice - 1]

    # Output path
    from core.config import REPORTS_DIR
    from datetime import datetime
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_path = str(REPORTS_DIR / f"report_{sess_id[:8]}_{ts}.{fmt}")
    out_path = get_input("Output path", default_path)

    info(f"Generating {cyan(fmt.upper())} report…")

    try:
        from core.database import get_db
        db   = get_db()
        data = {
            "session":         db.get_session(sess_id),
            "hosts":           db.get_session_hosts(sess_id),
            "ports":           db.get_session_ports(sess_id),
            "vulnerabilities": db.get_session_vulns(sess_id),
            "credentials":     db.get_session_creds(sess_id),
            "classification":  classif,
        }
    except Exception as e:
        error_msg(f"Database error: {e}")
        wait_enter()
        return

    try:
        from modules.report_generator import ReportGenerator
        ReportGenerator().generate(data=data, fmt=fmt, output_path=out_path)
        success_msg(f"Report saved: {out_path}")
    except Exception as e:
        error_msg(f"Report generation error: {e}")
    wait_enter()


# ── Export JSON ────────────────────────────────────────────────────────────────

def _export_json(sessions: list) -> None:
    if not sessions:
        warn_msg("No sessions available.")
        wait_enter()
        return

    choice = get_choice(len(sessions), "Select session (0=all)")
    if choice is None:
        return

    from core.config import REPORTS_DIR
    from datetime import datetime
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        from core.database import get_db
        db = get_db()

        if choice == 0:
            export_sessions = sessions
            out_path = str(REPORTS_DIR / f"sessions_all_{ts}.json")
        else:
            export_sessions = [sessions[choice - 1]]
            sid = export_sessions[0].get("id", "")[:8]
            out_path = str(REPORTS_DIR / f"session_{sid}_{ts}.json")

        out_path = get_input("Output path", out_path)

        export_data = []
        for s in export_sessions:
            sid = s.get("id", "")
            export_data.append({
                "session":     s,
                "hosts":       db.get_session_hosts(sid),
                "ports":       db.get_session_ports(sid),
                "vulns":       db.get_session_vulns(sid),
                "credentials": db.get_session_creds(sid),
            })

        with open(out_path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)
        success_msg(f"Exported {len(export_data)} session(s) to {out_path}")
    except Exception as e:
        error_msg(f"Export error: {e}")
    wait_enter()


# ── Delete session ─────────────────────────────────────────────────────────────

def _delete_session(sessions: list) -> list:
    if not sessions:
        warn_msg("No sessions to delete.")
        wait_enter()
        return sessions

    choice = get_choice(len(sessions), "Select session to delete (0=cancel)")
    if not choice or choice == 0:
        return sessions

    s       = sessions[choice - 1]
    sess_id = s.get("id", "")
    ssid    = s.get("target_ssid", "?")

    if not ask_yn(f"Delete session {cyan(sess_id[:12])} ({ssid})? This cannot be undone."):
        return sessions

    try:
        from core.database import get_db
        db = get_db()
        if hasattr(db, "delete_session"):
            db.delete_session(sess_id)
            success_msg(f"Session {sess_id[:12]} deleted.")
            return [s for s in sessions if s.get("id") != sess_id]
        else:
            warn_msg("delete_session() not available in this database version.")
    except Exception as e:
        error_msg(f"Delete error: {e}")
    wait_enter()
    return sessions


# ── Top-level History menu ─────────────────────────────────────────────────────

def history_menu() -> None:
    sessions: list = []

    while True:
        print_section("SESSION HISTORY")
        sessions = _list_sessions()

        print_menu("HISTORY OPTIONS", [
            "View Session Detail",
            "Generate Report       — PDF / HTML / JSON / TXT",
            "Export JSON           — raw data export",
            "Delete Session",
            "Refresh",
        ])
        choice = get_choice(5)
        if choice is None:
            continue
        if choice == 0:
            break
        elif choice == 1:
            _view_session(sessions)
        elif choice == 2:
            _generate_report(sessions)
        elif choice == 3:
            _export_json(sessions)
        elif choice == 4:
            sessions = _delete_session(sessions)
        elif choice == 5:
            pass  # loop will refresh
