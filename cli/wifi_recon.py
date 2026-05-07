"""
cli/wifi_recon.py — Passive WiFi Reconnaissance
Captures beacon frames, probe requests, deauth frames, and RF environment analysis.
"""
import os
import re
import time
import subprocess
import threading
import tempfile
import csv
from collections import defaultdict


def run_recon(interface: str, duration: int = 60) -> None:
    """
    Passive reconnaissance mode.
    Captures beacons, probe requests, deauth frames, channel utilization.
    """
    print(f"\n  [RECON]  Passive WiFi reconnaissance on {interface} ({duration}s)")
    print("  " + "─" * 60)

    tmpdir     = tempfile.mkdtemp(prefix="dc_recon_")
    csv_prefix = os.path.join(tmpdir, "recon")
    deauth_cap = os.path.join(tmpdir, "deauth.pcapng")

    # ── Phase 1: Launch airodump-ng for full capture ─────────────────────────
    airodump_cmd = [
        "airodump-ng",
        "--output-format", "csv",
        "-w", csv_prefix,
        "--write-interval", "5",
        interface,
    ]

    print(f"  [+]  Starting airodump-ng (duration: {duration}s)…")
    try:
        airo_proc = subprocess.Popen(
            airodump_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        print("  [!]  airodump-ng not found — install aircrack-ng suite")
        return
    except Exception as exc:
        print(f"  [!]  Failed to start airodump-ng: {exc}")
        return

    # ── Phase 2: Launch tshark in parallel for deauth frame detection ─────────
    deauth_count = [0]
    deauth_lock  = threading.Lock()
    tshark_proc  = None

    try:
        tshark_cmd = [
            "tshark",
            "-i", interface,
            "-f", "subtype deauth",
            "-a", f"duration:{duration}",
            "-w", deauth_cap,
        ]
        tshark_proc = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print("  [+]  tshark deauth capture started")
    except FileNotFoundError:
        print("  [!]  tshark not available — deauth detection skipped")
    except Exception as exc:
        print(f"  [!]  tshark error: {exc}")

    # ── Wait for capture duration ──────────────────────────────────────────────
    print(f"  [+]  Capturing for {duration}s…  (Ctrl-C to stop early)")
    start = time.time()
    try:
        while time.time() - start < duration:
            elapsed = int(time.time() - start)
            remaining = duration - elapsed
            print(f"\r  [~]  {elapsed}s / {duration}s elapsed ({remaining}s remaining)…", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n  [!]  Interrupted — analyzing partial results…")

    print()

    # ── Stop processes ────────────────────────────────────────────────────────
    for proc in (airo_proc, tshark_proc):
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    # ── Parse CSV ─────────────────────────────────────────────────────────────
    csv_file = csv_prefix + "-01.csv"
    if not os.path.exists(csv_file):
        print(f"  [!]  No CSV output found at {csv_file}")
        return

    try:
        with open(csv_file, "r", errors="replace") as fh:
            raw = fh.read()
    except Exception as exc:
        print(f"  [!]  Could not read CSV: {exc}")
        return

    sections = re.split(r"\n\s*\n", raw, maxsplit=1)
    ap_section     = sections[0] if sections else ""
    client_section = sections[1] if len(sections) > 1 else ""

    # Parse APs
    aps = []
    for row in csv.reader(ap_section.splitlines()):
        if len(row) < 14:
            continue
        bssid = row[0].strip().upper()
        if bssid in ("BSSID", "") or not re.match(r"([0-9A-F]{2}:){5}[0-9A-F]{2}", bssid):
            continue
        try:
            channel = int(row[3].strip())
        except ValueError:
            channel = 0
        enc     = row[5].strip()
        power   = row[8].strip()
        try:
            pwr_int = int(power)
        except ValueError:
            pwr_int = -100
        ssid_raw = row[13].strip() if len(row) > 13 else ""
        try:
            id_len = int(row[12].strip())
        except (ValueError, IndexError):
            id_len = 0
        ssid = ssid_raw if (ssid_raw and id_len > 0) else "<hidden>"
        aps.append({
            "bssid":   bssid,
            "ssid":    ssid,
            "channel": channel,
            "enc":     enc,
            "power":   pwr_int,
        })

    # Parse clients / probe requests
    probe_ssids: dict = defaultdict(set)  # station_mac → set of probed SSIDs
    for row in csv.reader(client_section.splitlines()):
        if len(row) < 7:
            continue
        station = row[0].strip()
        if station in ("Station MAC", "") or not re.match(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", station):
            continue
        probed = row[6].strip() if len(row) > 6 else ""
        if probed:
            for s in probed.split(","):
                s = s.strip()
                if s:
                    probe_ssids[station].add(s)

    # Channel utilization
    channel_counts: dict = defaultdict(int)
    for ap in aps:
        if 1 <= ap["channel"] <= 13:
            channel_counts[ap["channel"]] += 1

    # Count deauth frames via tshark read-back
    if os.path.exists(deauth_cap) and os.path.getsize(deauth_cap) > 0:
        try:
            rc, out, _ = _run_sync(
                ["tshark", "-r", deauth_cap, "-T", "fields", "-e", "frame.number"],
                timeout=15,
            )
            deauth_count[0] = len([l for l in out.splitlines() if l.strip()])
        except Exception:
            pass

    # ── Print summary ─────────────────────────────────────────────────────────
    sep  = "=" * 64
    thin = "-" * 64
    print(f"\n{sep}")
    print(f"  PASSIVE RECON RESULTS — {interface}")
    print(sep)

    # Beacons / APs
    print(f"\n  APs FOUND ({len(aps)} total)")
    print(thin)
    print(f"  {'SSID':<30}  {'BSSID':<20}  {'CH':>3}  {'ENC':<8}  {'POWER':>6}")
    print("  " + "-" * 60)
    for ap in sorted(aps, key=lambda x: x["power"], reverse=True):
        print(
            f"  {ap['ssid']:<30}  {ap['bssid']:<20}  "
            f"{str(ap['channel']):>3}  {ap['enc']:<8}  {ap['power']:>6} dBm"
        )

    # Probe requests
    print(f"\n  PROBE REQUESTS (devices searching for SSIDs)")
    print(thin)
    if probe_ssids:
        for station, ssids in list(probe_ssids.items())[:20]:
            print(f"  {station:<20}  → {', '.join(sorted(ssids))}")
    else:
        print("  (none captured)")

    # Channel utilization bar chart
    print(f"\n  CHANNEL UTILIZATION (2.4 GHz)")
    print(thin)
    max_count = max(channel_counts.values(), default=1)
    for ch in range(1, 14):
        count = channel_counts.get(ch, 0)
        bar   = "█" * int((count / max_count) * 30) if max_count else ""
        print(f"  CH{ch:>2}  {bar:<30}  {count} AP(s)")

    # Deauth frames
    print(f"\n  DEAUTHENTICATION FRAMES")
    print(thin)
    if deauth_count[0] > 0:
        print(f"  [!]  Detected {deauth_count[0]} deauth frames — possible deauth attack in progress!")
    else:
        print(f"  No deauth frames detected during capture period.")

    print(f"\n{sep}\n")

    # Cleanup
    try:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    except Exception:
        pass


def _run_sync(cmd: list, timeout: int = 30):
    """Run command synchronously and return (rc, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except FileNotFoundError:
        return -1, "", f"Not found: {cmd[0]}"
    except Exception as exc:
        return -1, "", str(exc)
