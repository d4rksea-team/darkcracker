"""
modules/interface_manager.py — DARK CRACKER OPS Generation 2
Wireless interface management: detection, monitor mode, injection testing,
channel control, and interface metadata retrieval.
"""

import re
import subprocess
from core.config import TOOLS
from core.logger import get_logger

log = get_logger("interface_manager")


class InterfaceManager:
    """
    Manages wireless network interfaces — enabling/disabling monitor mode,
    querying capabilities, and setting operational parameters.
    All methods are synchronous and called from the main thread or a worker.
    """

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _run(cmd: list, timeout: int = 15) -> tuple[int, str, str]:
        """Run a command and return (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", f"Executable not found: {cmd[0]}"
        except Exception as exc:
            return -1, "", str(exc)

    # ── Public API ────────────────────────────────────────────────────────────

    def detect_interfaces(self) -> list:
        """
        Return a list of wireless interfaces with capability metadata.

        Each entry:
            {
                "name": str,
                "mode": str,             # managed | monitor | AP | …
                "supports_monitor": bool,
                "supports_injection": bool,
            }
        """
        interfaces = []

        # 1. Enumerate interfaces via `iw dev`
        rc, stdout, _ = self._run(["iw", "dev"])
        if rc != 0:
            log.warning("iw dev failed — no wireless interfaces found")
            return interfaces

        iface_blocks = re.split(r"(?=Interface\s)", stdout)
        iface_names = []
        iface_modes = {}

        for block in iface_blocks:
            name_match = re.search(r"Interface\s+(\S+)", block)
            mode_match = re.search(r"type\s+(\S+)", block)
            if name_match:
                name = name_match.group(1)
                mode = mode_match.group(1) if mode_match else "unknown"
                iface_names.append(name)
                iface_modes[name] = mode

        # 2. Query physical capabilities per interface via `iw phy`
        rc_phy, phy_stdout, _ = self._run(["iw", "phy"])
        phy_text = phy_stdout if rc_phy == 0 else ""

        # Determine which phys support monitor mode
        # `iw phy` output groups capabilities under each phy block
        phy_blocks = re.split(r"(?=Wiphy\s)", phy_text)
        # Build phy→iface mapping via `iw dev` block that contains phy name
        phy_iface_map: dict[str, list] = {}
        for chunk in re.split(r"(?=phy#\d+)", stdout):
            phy_match = re.search(r"phy#(\d+)", chunk)
            if not phy_match:
                continue
            phy_id = f"phy{phy_match.group(1)}"
            ifaces_in_chunk = re.findall(r"Interface\s+(\S+)", chunk)
            phy_iface_map.setdefault(phy_id, []).extend(ifaces_in_chunk)

        # Parse monitor support from phy blocks
        phy_monitor: dict[str, bool] = {}
        for block in phy_blocks:
            phy_match = re.search(r"Wiphy\s+(\S+)", block)
            if not phy_match:
                continue
            phy_name = phy_match.group(1)
            phy_monitor[phy_name] = "monitor" in block.lower()

        # Map phy monitor capability back to interface names
        iface_monitor: dict[str, bool] = {}
        for phy_name, ifaces in phy_iface_map.items():
            # Match Wiphy phyN ↔ phy#N
            phy_key = phy_name.replace("#", "")
            cap = phy_monitor.get(phy_key, False)
            for iface in ifaces:
                iface_monitor[iface] = cap

        # If phy→iface map is incomplete, default True for common chipsets
        for name in iface_names:
            if name not in iface_monitor:
                iface_monitor[name] = True  # Optimistic — most wireless NICs do

        for name in iface_names:
            interfaces.append({
                "name": name,
                "mode": iface_modes.get(name, "unknown"),
                "supports_monitor": iface_monitor.get(name, False),
                "supports_injection": False,  # Determined by check_injection()
            })

        log.info("Detected %d wireless interface(s): %s",
                 len(interfaces), [i["name"] for i in interfaces])
        return interfaces

    def enable_monitor_mode(self, iface: str) -> tuple[bool, str]:
        """
        Bring interface into monitor mode using airmon-ng.

        Returns:
            (True, "wlan0mon")  on success
            (False, error_msg) on failure
        """
        airmon = TOOLS.get("airmon", "airmon-ng")

        # Kill processes that interfere with monitor mode (NetworkManager, wpa_supplicant)
        self._run([airmon, "check", "kill"], timeout=15)

        rc, stdout, stderr = self._run([airmon, "start", iface], timeout=30)

        if rc != 0:
            err = stderr.strip() or stdout.strip() or "airmon-ng returned non-zero"
            log.error("enable_monitor_mode(%s) failed: %s", iface, err)
            return False, err

        # Get real interface list AFTER airmon-ng runs so we can validate names
        _, iw_out, _ = self._run(["iw", "dev"])

        # Parse interfaces currently in monitor mode from iw dev output
        monitor_ifaces = re.findall(
            r"Interface\s+(\S+).*?type\s+monitor",
            iw_out, re.DOTALL | re.IGNORECASE
        )

        # If the original iface is now in monitor mode, use it directly
        if iface in monitor_ifaces:
            log.info("Monitor mode confirmed on original interface: %s", iface)
            return True, iface

        # If a "mon" variant exists, prefer it
        candidate = iface + "mon"
        if candidate in monitor_ifaces:
            log.info("Monitor mode enabled (fallback detection): %s", candidate)
            return True, candidate

        # Any monitor interface found after the airmon-ng call
        if monitor_ifaces:
            mon_iface = monitor_ifaces[0]
            log.info("Monitor interface detected: %s", mon_iface)
            return True, mon_iface

        # Parse airmon-ng stdout as last resort — only accept names that look like
        # real interfaces (contain letters, not purely numeric channel numbers)
        patterns = [
            r"enabled on\s+([a-zA-Z]\w+)",
            r"enabled for\s+\[\w+\]\w+\s+on\s+(?:\[\w+\])?([a-zA-Z]\w+)",
            r"monitor mode.*?on\s+(?:\[\w+\])?([a-zA-Z]\w+mon\w*)",
        ]
        for pat in patterns:
            m = re.search(pat, stdout, re.IGNORECASE)
            if m:
                mon_iface = m.group(1)
                if re.match(r"^[a-zA-Z]", mon_iface):   # must start with a letter
                    log.info("Monitor mode enabled (stdout parse): %s → %s", iface, mon_iface)
                    return True, mon_iface

        # Final fallback: return original interface (some drivers rename in-place)
        log.warning("Could not detect monitor interface — using original: %s", iface)
        return True, iface

    def disable_monitor_mode(self, iface: str) -> bool:
        """
        Stop monitor mode on iface using airmon-ng stop.

        Returns True on success, False on failure.
        """
        airmon = TOOLS.get("airmon", "airmon-ng")
        rc, stdout, stderr = self._run([airmon, "stop", iface], timeout=30)
        if rc != 0:
            log.error("disable_monitor_mode(%s) failed: %s", iface,
                      stderr.strip() or stdout.strip())
            return False
        log.info("Monitor mode disabled on %s", iface)
        return True

    def check_injection(self, iface: str) -> tuple[bool, str]:
        """
        Test packet injection capability via aireplay-ng --test.

        Returns:
            (True, output)  if injection works
            (False, output) if injection fails or is unsupported
        """
        aireplay = TOOLS.get("aireplay", "aireplay-ng")
        rc, stdout, stderr = self._run(
            [aireplay, "--test", iface], timeout=30
        )
        combined = stdout + stderr

        # aireplay-ng exits 0 on success and prints "Injection is working!"
        success = (
            "injection is working" in combined.lower()
            or "attack -0" in combined.lower()
        )
        if success:
            log.info("Injection test PASSED on %s", iface)
        else:
            log.warning("Injection test FAILED on %s", iface)

        return success, combined.strip()

    def set_channel(self, iface: str, channel: int) -> bool:
        """
        Set the wireless channel using iwconfig.

        Returns True on success, False on failure.
        """
        rc, _, stderr = self._run(
            ["iwconfig", iface, "channel", str(channel)]
        )
        if rc != 0:
            log.error("set_channel(%s, %d) failed: %s", iface, channel, stderr.strip())
            return False
        log.debug("Channel set to %d on %s", channel, iface)
        return True

    def get_interface_info(self, iface: str) -> dict:
        """
        Return interface metadata dict:
            {name, mac, mode, channel, txpower}
        Combines output from `iw dev {iface} info` and `iwconfig {iface}`.
        """
        info = {
            "name": iface,
            "mac": "unknown",
            "mode": "unknown",
            "channel": 0,
            "txpower": "unknown",
        }

        # `iw dev {iface} info` — reliable for mode/channel/MAC
        rc, stdout, _ = self._run(["iw", "dev", iface, "info"])
        if rc == 0:
            mac_m = re.search(r"addr\s+([0-9a-f:]{17})", stdout, re.IGNORECASE)
            mode_m = re.search(r"type\s+(\S+)", stdout)
            chan_m = re.search(r"channel\s+(\d+)", stdout)
            if mac_m:
                info["mac"] = mac_m.group(1).upper()
            if mode_m:
                info["mode"] = mode_m.group(1)
            if chan_m:
                info["channel"] = int(chan_m.group(1))

        # `iwconfig {iface}` — txpower and fallback channel
        rc2, iw_out, _ = self._run(["iwconfig", iface])
        if rc2 == 0:
            txpow_m = re.search(r"Tx-Power[=:]\s*(\S+)", iw_out, re.IGNORECASE)
            if txpow_m:
                info["txpower"] = txpow_m.group(1)
            if info["channel"] == 0:
                chan_m2 = re.search(r"Frequency[:\s]+[\d.]+\s+GHz.*?Channel\s+(\d+)",
                                    iw_out, re.IGNORECASE)
                if chan_m2:
                    info["channel"] = int(chan_m2.group(1))

        log.debug("Interface info for %s: %s", iface, info)
        return info
