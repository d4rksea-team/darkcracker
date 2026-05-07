"""
modules/cred_manager.py — Credential storage and analysis manager.
DARK CRACKER OPS Generation 2
"""
import re
from typing import Optional

from core.database import Database

# ── Top-100 most common passwords ────────────────────────────────────────────
COMMON_PASSWORDS: set[str] = {
    "123456", "password", "123456789", "12345678", "12345",
    "1234567", "1234567890", "qwerty", "abc123", "111111",
    "123123", "admin", "letmein", "monkey", "1234",
    "dragon", "master", "sunshine", "ashley", "bailey",
    "passw0rd", "shadow", "123321", "654321", "superman",
    "qazwsx", "michael", "football", "baseball", "soccer",
    "charlie", "donald", "password1", "qwerty123", "iloveyou",
    "batman", "aa123456", "starwars", "hello", "welcome",
    "login", "admin123", "pass", "test", "access",
    "666666", "888888", "princess", "jessica", "thomas",
    "whatever", "trustno1", "welcome1", "qwertyuiop", "flower",
    "hottie", "loveme", "zxcvbnm", "buster", "george",
    "robert", "daniel", "andrew", "jordan", "harley",
    "ranger", "dakota", "maverick", "cookie", "cheese",
    "hunter", "thunder", "tigger", "ginger", "samuel",
    "joshua", "matthew", "brandon", "william", "jessica1",
    "password2", "freedom", "phoenix", "yankees", "angels",
    "golfer", "muster", "mercedes", "arsenal", "chelsea",
    "liverpool", "hockey", "lakers", "cowboys", "steelers",
    "123qwe", "000000", "1q2w3e", "qwe123", "test123",
    "root", "toor", "kali", "parrot", "ubuntu",
    "raspberry", "pi", "admin1", "1admin", "nimda",
}


class CredentialManager:
    """
    Manages credential storage and password analysis.

    Uses the shared Database instance for all persistence.
    """

    def __init__(self, db: Optional[Database] = None) -> None:
        """
        Parameters
        ----------
        db : existing Database instance, or None to create a new one
        """
        self._db = db or Database()

    # ── Storage helpers ───────────────────────────────────────────────────────

    def add_wifi_cred(
        self,
        session_id: str,
        ssid: str,
        bssid: str,
        password: str,
        enc_type: str,
    ) -> None:
        """
        Persist a cracked WiFi credential to the database.

        Parameters
        ----------
        session_id : active session UUID fragment
        ssid       : network name
        bssid      : AP MAC address
        password   : recovered passphrase
        enc_type   : WPA2, WPA3, WEP, OPN, etc.
        """
        target = f"{ssid} ({bssid})" if bssid else ssid
        self._db.add_credential(
            session_id=session_id,
            cred_type="wifi",
            target=target,
            username="",
            password=password,
            service=enc_type,
            port=0,
        )

    def add_service_cred(
        self,
        session_id: str,
        ip: str,
        port: int,
        service: str,
        username: str,
        password: str,
    ) -> None:
        """
        Persist a service-level credential (SSH, FTP, HTTP, etc.).

        Parameters
        ----------
        session_id : active session UUID fragment
        ip         : target host IP
        port       : target port number
        service    : service name (ssh, ftp, http, …)
        username   : account name
        password   : recovered password
        """
        self._db.add_credential(
            session_id=session_id,
            cred_type="service",
            target=ip,
            username=username,
            password=password,
            service=service,
            port=port,
        )

    # ── Password analysis ─────────────────────────────────────────────────────

    def analyze_password_strength(self, password: str) -> dict:
        """
        Score a password from 0 (empty) to 5 (excellent).

        Returns
        -------
        dict with keys: score (int), label (str), suggestions (list[str])
        """
        if not password:
            return {
                "score":       0,
                "label":       "Empty",
                "suggestions": ["A password is required."],
            }

        score       = 0
        suggestions = []
        length      = len(password)

        has_lower  = bool(re.search(r"[a-z]", password))
        has_upper  = bool(re.search(r"[A-Z]", password))
        has_digit  = bool(re.search(r"\d", password))
        has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
        char_types = sum([has_lower, has_upper, has_digit, has_symbol])

        # Score 1: too short
        if length < 6:
            return {
                "score":       1,
                "label":       "Very Weak",
                "suggestions": ["Use at least 8 characters.", "Mix character types."],
            }

        # Score 2: short or mono-type
        if length < 8 or char_types <= 1:
            score = 2
            label = "Weak"
            if length < 8:
                suggestions.append("Increase to at least 8 characters.")
            if not has_upper:
                suggestions.append("Add uppercase letters.")
            if not has_digit:
                suggestions.append("Add numbers.")
            if not has_symbol:
                suggestions.append("Add special characters (!@#$…).")
            return {"score": score, "label": label, "suggestions": suggestions}

        # Score 3: medium (8-11 chars, 2 types)
        if length < 12 or char_types == 2:
            score = 3
            label = "Medium"
            if length < 12:
                suggestions.append("Aim for 12+ characters.")
            if char_types < 3:
                suggestions.append("Use at least 3 character types.")
            return {"score": score, "label": label, "suggestions": suggestions}

        # Score 4: good (12-15 chars, 3+ types)
        if length < 16 or char_types < 4:
            score = 4
            label = "Strong"
            if length < 16:
                suggestions.append("16+ characters is ideal.")
            if not has_symbol:
                suggestions.append("Add special characters for maximum strength.")
            return {"score": score, "label": label, "suggestions": suggestions}

        # Score 5: excellent (16+ chars, all 4 types)
        return {
            "score":       5,
            "label":       "Excellent",
            "suggestions": [],
        }

    def check_common(self, password: str) -> bool:
        """
        Return True if the password appears in the top-100 common list
        (case-insensitive).
        """
        return password.lower() in COMMON_PASSWORDS

    # ── Statistics ────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        """
        Return aggregate credential counts from the database.

        Returns
        -------
        dict with keys:
            total_creds, wifi_creds, service_creds,
            unique_sessions, unique_targets
        """
        try:
            conn  = self._db._conn
            total = conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0]
            wifi  = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE cred_type='wifi'"
            ).fetchone()[0]
            svc   = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE cred_type='service'"
            ).fetchone()[0]
            sess  = conn.execute(
                "SELECT COUNT(DISTINCT session_id) FROM credentials"
            ).fetchone()[0]
            tgts  = conn.execute(
                "SELECT COUNT(DISTINCT target) FROM credentials"
            ).fetchone()[0]
            return {
                "total_creds":      total,
                "wifi_creds":       wifi,
                "service_creds":    svc,
                "unique_sessions":  sess,
                "unique_targets":   tgts,
            }
        except Exception as exc:
            return {
                "total_creds":     0,
                "wifi_creds":      0,
                "service_creds":   0,
                "unique_sessions": 0,
                "unique_targets":  0,
                "error":           str(exc),
            }
