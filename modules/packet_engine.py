from core.worker import BaseWorker
"""
modules/packet_engine.py — DARK CRACKER OPS Generation 2
Live packet capture and 802.11 frame analysis using Scapy AsyncSniffer.
Detects beacons, probe requests, deauth attacks, and EAPOL handshakes.
"""

import os
import queue
import struct
import threading
import time
from collections import defaultdict


from core.logger import get_logger

log = get_logger("packet_engine")

# Deauth detection threshold: frames from same BSSID within window
DEAUTH_BURST_THRESHOLD = 5     # frames
DEAUTH_BURST_WINDOW    = 10    # seconds

# Import Scapy lazily to avoid import-time RF_MONitor warnings
try:
    from scapy.all import (
        Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt,
        Dot11Deauth, EAPOL, wrpcap, AsyncSniffer,
        RadioTap,
    )
    _SCAPY_OK = True
except ImportError:
    _SCAPY_OK = False


class PacketEngine(BaseWorker):
    """
    Real-time 802.11 packet capture and frame classification.

    Uses Scapy's AsyncSniffer for non-blocking capture.
    All frame handlers enqueue work; the main run() loop drains
    and emits Qt signals — keeping signal emission on the QThread.

    Signals:
        log_message(str, str)       — (tag, message)
        probe_found(dict)           — {mac, ssids, vendor, timestamp}
        deauth_detected(dict)       — {bssid, reason, count, timestamp, is_attack}
        beacon_found(dict)          — {bssid, ssid, channel, rates, enc, power}
        handshake_detected(str)     — BSSID where EAPOL handshake seen
        eapol_count(int)            — running EAPOL frame total
        finished(bool)              — clean stop = True
    """

    # Platform contract

    def __init__(self, parent=None):
        super().__init__()
        self._stop     = False
        self._iface    = ""
        self._sniffer  = None         # Scapy AsyncSniffer instance

        # Accumulated capture store (for pcap export)
        self._packets  = []
        self._pkt_lock = threading.Lock()

        # Signal work queue — handlers push dicts, run() pops and emits
        self._queue: queue.Queue = queue.Queue()

        # Analysis state
        self.probe_map: dict[str, list]  = defaultdict(list)   # mac → [ssids]
        self.deauth_map: dict[str, list] = defaultdict(list)   # bssid → [timestamps]
        self._eapol_total                = 0
        self._eapol_per_bssid: dict[str, int] = defaultdict(int)
        self._known_bssids: set[str]     = set()

    # ── Configuration ─────────────────────────────────────────────────────────

    def start_capture(self, iface: str) -> None:
        """Set the capture interface. Call before start()."""
        self._iface = iface

    # ── QThread entry point ───────────────────────────────────────────────────

    def run(self):
        self._stop = False

        if not _SCAPY_OK:
            self._safe_emit("log_message", "ERROR",
                "scapy not installed — pip install scapy")
            self._safe_emit("finished", False)
            return

        if not self._iface:
            self._safe_emit("log_message", "ERROR",
                "No interface configured — call start_capture(iface) first")
            self._safe_emit("finished", False)
            return

        self._safe_emit("log_message", "PACKETS",
            f"Starting packet capture on {self._iface}")

        try:
            self._sniffer = AsyncSniffer(
                iface=self._iface,
                prn=self._packet_handler,
                store=False,    # we manage our own list
                monitor=True,
            )
            self._sniffer.start()
        except Exception as exc:
            self._safe_emit("log_message", "ERROR",
                f"AsyncSniffer failed to start: {exc}. "
                f"Ensure {self._iface} is in monitor mode.")
            self._safe_emit("finished", False)
            return

        self._safe_emit("log_message", "PACKETS", "Capture running…")

        # Main loop: drain work queue and emit signals
        while not self._stop:
            self._drain_queue()
            time.sleep(0.1)

        # Final drain after stop
        self._drain_queue()

        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
            self._sniffer = None

        self._safe_emit("log_message", "PACKETS",
            f"Capture stopped — {len(self._packets)} packets stored, "
            f"{self._eapol_total} EAPOL frames seen")
        self._safe_emit("finished", True)

    def _drain_queue(self) -> None:
        """Emit all pending signal work from the queue."""
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break

            sig  = item.get("signal")
            data = item.get("data")

            if sig == "probe_found" and data:
                self._safe_emit("probe_found", data)
            elif sig == "beacon_found" and data:
                self._safe_emit("beacon_found", data)
            elif sig == "deauth_detected" and data:
                self._safe_emit("deauth_detected", data)
            elif sig == "handshake_detected" and data:
                self._safe_emit("handshake_detected", data)
            elif sig == "eapol_count" and data is not None:
                self._safe_emit("eapol_count", data)
            elif sig == "log" and data:
                self._safe_emit("log_message", data[0], data[1])

    # ── Packet handler ─────────────────────────────────────────────────────────

    def _packet_handler(self, pkt) -> None:
        """
        Scapy packet callback — runs in the sniffer thread.
        Enqueues work for the main QThread loop.
        """
        if self._stop:
            return

        # Store for pcap export
        with self._pkt_lock:
            self._packets.append(pkt)

        if not pkt.haslayer(Dot11):
            return

        try:
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)
            elif pkt.haslayer(Dot11ProbeReq):
                self._handle_probe_req(pkt)
            elif pkt.haslayer(Dot11Deauth):
                self._handle_deauth(pkt)
            elif pkt.haslayer(EAPOL):
                self._handle_eapol(pkt)
        except Exception as exc:
            log.debug("Packet handler exception: %s", exc)

    # ── Frame handlers ────────────────────────────────────────────────────────

    def _handle_beacon(self, pkt) -> None:
        """Extract AP information from Dot11Beacon frames."""
        dot11 = pkt.getlayer(Dot11)
        bssid = dot11.addr3.upper() if dot11.addr3 else "FF:FF:FF:FF:FF:FF"

        # Extract SSID from Dot11Elt chain
        ssid = ""
        channel = 0
        rates   = []
        enc     = "OPEN"

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:     # SSID element
                try:
                    ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    ssid = ""
            elif elt.ID == 3:   # DS Parameter Set (channel)
                try:
                    channel = struct.unpack("B", elt.info)[0]
                except Exception:
                    pass
            elif elt.ID == 1 or elt.ID == 50:   # Supported / Extended rates
                for byte in elt.info:
                    rate_mbps = (byte & 0x7F) * 0.5
                    if rate_mbps not in rates:
                        rates.append(rate_mbps)
            elif elt.ID == 48:  # RSN (WPA2/WPA3)
                enc = self._parse_rsn(elt.info)
            elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":  # WPA1
                if enc == "OPEN":
                    enc = "WPA"
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                break

        if not ssid:
            ssid = "<hidden>"

        # Signal strength (RSSI) from RadioTap
        power = -100
        if pkt.haslayer(RadioTap):
            rt = pkt.getlayer(RadioTap)
            try:
                power = rt.dBm_AntSignal
            except AttributeError:
                pass

        beacon_data = {
            "bssid":   bssid,
            "ssid":    ssid,
            "channel": channel,
            "rates":   sorted(rates),
            "enc":     enc,
            "power":   power,
            "timestamp": time.strftime("%H:%M:%S"),
        }

        # Emit only if new or channel/enc changed
        cache_key = f"{bssid}:{channel}:{enc}"
        if cache_key not in self._known_bssids:
            self._known_bssids.add(cache_key)
            self._queue.put({"signal": "beacon_found", "data": beacon_data})
            self._queue.put({"signal": "log", "data": [
                "BEACON",
                f"AP: {ssid} ({bssid}) CH:{channel} {enc} {power}dBm"
            ]})

    def _handle_probe_req(self, pkt) -> None:
        """Extract client MAC and probed SSIDs from Dot11ProbeReq frames."""
        dot11 = pkt.getlayer(Dot11)
        src_mac = dot11.addr2.upper() if dot11.addr2 else "00:00:00:00:00:00"

        probed_ssid = ""
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    probed_ssid = elt.info.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    probed_ssid = ""
                break
            try:
                elt = elt.payload.getlayer(Dot11Elt)
            except Exception:
                break

        if probed_ssid and probed_ssid not in self.probe_map[src_mac]:
            self.probe_map[src_mac].append(probed_ssid)

        probe_data = {
            "mac":       src_mac,
            "ssids":     list(self.probe_map[src_mac]),
            "vendor":    self._oui_lookup(src_mac),
            "timestamp": time.strftime("%H:%M:%S"),
        }
        self._queue.put({"signal": "probe_found", "data": probe_data})

        if probed_ssid:
            self._queue.put({"signal": "log", "data": [
                "PROBE",
                f"Client {src_mac} probing for '{probed_ssid}'"
            ]})

    def _handle_deauth(self, pkt) -> None:
        """
        Detect deauthentication frames.
        Identifies burst attacks when count exceeds DEAUTH_BURST_THRESHOLD
        within DEAUTH_BURST_WINDOW seconds.
        """
        dot11  = pkt.getlayer(Dot11)
        deauth = pkt.getlayer(Dot11Deauth)

        bssid  = dot11.addr3.upper() if dot11.addr3 else \
                 dot11.addr2.upper() if dot11.addr2 else "FF:FF:FF:FF:FF:FF"
        reason = deauth.reason if deauth else 0

        now = time.time()
        self.deauth_map[bssid].append(now)

        # Trim old timestamps outside the window
        cutoff = now - DEAUTH_BURST_WINDOW
        self.deauth_map[bssid] = [t for t in self.deauth_map[bssid] if t >= cutoff]

        burst_count = len(self.deauth_map[bssid])
        is_attack   = burst_count >= DEAUTH_BURST_THRESHOLD

        deauth_data = {
            "bssid":     bssid,
            "reason":    reason,
            "count":     burst_count,
            "timestamp": time.strftime("%H:%M:%S"),
            "is_attack": is_attack,
        }
        self._queue.put({"signal": "deauth_detected", "data": deauth_data})

        if is_attack and burst_count == DEAUTH_BURST_THRESHOLD:
            self._queue.put({"signal": "log", "data": [
                "DEAUTH",
                f"ATTACK DETECTED — {bssid} deauth burst: {burst_count} frames "
                f"(reason={reason})"
            ]})
        elif is_attack and burst_count % 10 == 0:
            self._queue.put({"signal": "log", "data": [
                "DEAUTH",
                f"Ongoing deauth storm on {bssid}: {burst_count} frames"
            ]})

    def _handle_eapol(self, pkt) -> None:
        """
        Count EAPOL frames per BSSID for handshake detection.
        A 4-way handshake requires 4 EAPOL frames (M1→M4).
        """
        dot11 = pkt.getlayer(Dot11)
        bssid = dot11.addr3.upper() if dot11.addr3 else \
                dot11.addr1.upper() if dot11.addr1 else "FF:FF:FF:FF:FF:FF"

        self._eapol_total           += 1
        self._eapol_per_bssid[bssid] += 1

        self._queue.put({"signal": "eapol_count", "data": self._eapol_total})

        # Emit handshake_detected once per BSSID when we see >= 4 EAPOL frames
        bssid_eapol = self._eapol_per_bssid[bssid]
        if bssid_eapol == 4:
            self._queue.put({"signal": "handshake_detected", "data": bssid})
            self._queue.put({"signal": "log", "data": [
                "EAPOL",
                f"Handshake detected on {bssid} ({bssid_eapol} EAPOL frames)"
            ]})
        elif bssid_eapol % 100 == 0:
            self._queue.put({"signal": "log", "data": [
                "EAPOL",
                f"EAPOL count for {bssid}: {bssid_eapol} (total: {self._eapol_total})"
            ]})

    # ── RSN parser ────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_rsn(rsn_bytes: bytes) -> str:
        """
        Parse RSN IE (ID=48) to determine encryption type.
        Returns "WPA3", "WPA2", "WPA", or "OPEN".
        """
        if len(rsn_bytes) < 4:
            return "WPA2"
        try:
            # Skip version (2 bytes) + group cipher suite (4 bytes)
            offset = 2
            if len(rsn_bytes) < offset + 4:
                return "WPA2"
            offset += 4  # group cipher

            # Pairwise cipher count
            if len(rsn_bytes) < offset + 2:
                return "WPA2"
            pairwise_count = struct.unpack_from("<H", rsn_bytes, offset)[0]
            offset += 2 + pairwise_count * 4

            # AKM suite count
            if len(rsn_bytes) < offset + 2:
                return "WPA2"
            akm_count = struct.unpack_from("<H", rsn_bytes, offset)[0]
            offset += 2

            akm_types = []
            for _ in range(akm_count):
                if len(rsn_bytes) < offset + 4:
                    break
                suite = rsn_bytes[offset:offset + 4]
                akm_type = suite[3]
                akm_types.append(akm_type)
                offset += 4

            # AKM type 8 = SAE (WPA3), type 2 = PSK (WPA2), type 1 = 802.1X
            if 8 in akm_types and 2 in akm_types:
                return "WPA3-Transition"
            elif 8 in akm_types:
                return "WPA3-SAE"
            elif 1 in akm_types:
                return "WPA2-Enterprise"
            else:
                return "WPA2"
        except Exception:
            return "WPA2"

    # ── OUI vendor lookup ─────────────────────────────────────────────────────

    @staticmethod
    def _oui_lookup(mac: str) -> str:
        """Attempt vendor lookup — delegates to core.utils if available."""
        try:
            from core.utils import get_vendor
            return get_vendor(mac)
        except Exception:
            return "Unknown"

    # ── PCAP export ───────────────────────────────────────────────────────────

    def export_pcap(self, path: str) -> bool:
        """
        Save all captured packets to a pcap file.

        Returns True on success, False on failure.
        """
        with self._pkt_lock:
            pkts = list(self._packets)

        if not pkts:
            log.warning("export_pcap: no packets to save")
            self._safe_emit("log_message", "PACKETS", "No packets captured — nothing to export")
            return False

        if not _SCAPY_OK:
            self._safe_emit("log_message", "ERROR", "scapy not available — cannot export pcap")
            return False

        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            wrpcap(path, pkts)
            self._safe_emit("log_message", "PACKETS",
                f"Exported {len(pkts)} packets → {path}")
            log.info("PCAP exported: %s (%d packets)", path, len(pkts))
            return True
        except Exception as exc:
            self._safe_emit("log_message", "ERROR", f"PCAP export failed: {exc}")
            log.error("PCAP export error: %s", exc)
            return False

    def stop_capture(self) -> None:
        """Alias for stop() — stop the sniffer and the thread."""
        self.stop()

    # ── Public control API ────────────────────────────────────────────────────

    def _safe_emit(self, sig, *a):
        pass

    def stop(self) -> None:
        """Stop packet capture."""
        self._stop = True
        if self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass
