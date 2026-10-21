"""Local URLhaus feed correlation and opt-in VirusTotal reputation lookups."""

from __future__ import annotations

import csv
import ipaddress
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from src.security.secret_store import WindowsSecretStore
from src.storage.database import SQLiteDatabase

_URLHAUS_EXPORT_URL = (
    "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"
)
_VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"
_MAX_FEED_BYTES = 32 * 1024 * 1024
_MAX_FEED_ROWS = 250_000
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ReputationError(RuntimeError):
    """Raised when a configured reputation source cannot be queried safely."""


@dataclass(frozen=True, slots=True)
class ReputationResult:
    indicator_type: str
    value: str
    provider: str
    verdict: str
    malicious: int | None
    suspicious: int | None
    detail: str
    checked_at: str


class ReputationService:
    def __init__(
        self,
        database: SQLiteDatabase,
        secret_store: WindowsSecretStore,
    ) -> None:
        self.database = database
        self.secret_store = secret_store

    @property
    def urlhaus_configured(self) -> bool:
        return self.secret_store.contains("urlhaus_auth_key")

    @property
    def virustotal_configured(self) -> bool:
        return self.secret_store.contains("virustotal_api_key")

    def save_urlhaus_key(self, key: str) -> None:
        self._save_secret("urlhaus_auth_key", key)

    def save_virustotal_key(self, key: str) -> None:
        self._save_secret("virustotal_api_key", key)

    def delete_urlhaus_key(self) -> bool:
        return self.secret_store.delete("urlhaus_auth_key")

    def delete_virustotal_key(self) -> bool:
        return self.secret_store.delete("virustotal_api_key")

    def sync_urlhaus(self) -> int:
        key = self._secret_text("urlhaus_auth_key")
        if not key:
            raise ReputationError(
                "Configure a URLhaus Auth-Key before synchronizing the feed."
            )
        previous = self.database.fetchone(
            "SELECT updated_at FROM reputation_feed_status WHERE provider = 'urlhaus'"
        )
        if previous is not None:
            try:
                last_update = datetime.fromisoformat(previous["updated_at"])
            except (TypeError, ValueError):
                last_update = datetime.min.replace(tzinfo=UTC)
            if last_update.tzinfo is None:
                last_update = last_update.replace(tzinfo=UTC)
            if datetime.now(UTC) - last_update < timedelta(minutes=5):
                raise ReputationError(
                    "URLhaus feed was synchronized less than five minutes ago; "
                    "wait before requesting another download."
                )
        endpoint = _URLHAUS_EXPORT_URL.format(auth_key=urllib.parse.quote(key, safe=""))
        request = urllib.request.Request(
            endpoint,
            headers={"User-Agent": "PrivSentinel/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=45) as response:
                feed_data = _read_bounded(response, _MAX_FEED_BYTES)
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            message = str(exc).replace(key, "[redacted]")
            raise ReputationError(f"URLhaus feed synchronization failed: {message}") from exc

        indicators = _parse_urlhaus_csv(feed_data)
        if not indicators:
            raise ReputationError(
                "URLhaus returned no usable active indicators; the existing feed was kept."
            )
        now = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            connection.execute(
                "DELETE FROM reputation_indicators WHERE provider = 'urlhaus'"
            )
            connection.executemany(
                "INSERT INTO reputation_indicators "
                "(provider, indicator_type, value, verdict, first_seen, last_seen) "
                "VALUES ('urlhaus', ?, ?, 'malicious', ?, ?) "
                "ON CONFLICT(provider, indicator_type, value) DO UPDATE SET "
                "last_seen = excluded.last_seen",
                [(kind, value, now, now) for kind, value in indicators],
            )
            connection.execute(
                "INSERT INTO reputation_feed_status (provider, updated_at, entry_count) "
                "VALUES ('urlhaus', ?, ?) "
                "ON CONFLICT(provider) DO UPDATE SET updated_at = excluded.updated_at, "
                "entry_count = excluded.entry_count",
                (now, len(indicators)),
            )
        return len(indicators)

    def check_urlhaus(self, url: str) -> ReputationResult | None:
        normalized_url, hostname = normalize_url(url)
        candidates = (("url", normalized_url), ("domain", hostname))
        for kind, value in candidates:
            if not value:
                continue
            row = self.database.fetchone(
                "SELECT value, first_seen, last_seen FROM reputation_indicators "
                "WHERE provider = 'urlhaus' AND indicator_type = ? AND value = ? "
                "LIMIT 1",
                (kind, value),
            )
            if row is not None:
                return ReputationResult(
                    kind,
                    value,
                    "URLhaus",
                    "malicious",
                    1,
                    0,
                    f"Listed in the local URLhaus feed (seen {row['first_seen']}).",
                    datetime.now(UTC).isoformat(),
                )
        return None

    def lookup_virustotal(
        self,
        indicator_type: str,
        value: str,
        use_cache: bool = True,
    ) -> ReputationResult:
        normalized_type, normalized_value, resource = _validate_indicator(
            indicator_type,
            value,
        )
        if use_cache:
            cached = self._cached_virustotal(normalized_type, normalized_value)
            if cached is not None:
                return cached
        key = self._secret_text("virustotal_api_key")
        if not key:
            raise ReputationError(
                "Configure a VirusTotal API key before requesting external reputation."
            )
        request = urllib.request.Request(
            f"{_VIRUSTOTAL_BASE_URL}/{resource}",
            headers={
                "User-Agent": "PrivSentinel/1.0",
                "x-apikey": key,
                "Accept": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = _read_bounded(response, 2 * 1024 * 1024)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                result = ReputationResult(
                    normalized_type,
                    normalized_value,
                    "VirusTotal",
                    "no_record",
                    0,
                    0,
                    "VirusTotal has no report for this indicator.",
                    datetime.now(UTC).isoformat(),
                )
                self._cache_virustotal(result)
                return result
            if exc.code == 429:
                raise ReputationError(
                    "VirusTotal rate limit reached; try again after its quota resets."
                ) from exc
            raise ReputationError(
                f"VirusTotal returned HTTP {exc.code}."
            ) from exc
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            raise ReputationError(f"VirusTotal lookup failed: {exc}") from exc

        try:
            decoded = json.loads(payload.decode("utf-8"))
            attributes = decoded["data"]["attributes"]
            stats = attributes.get("last_analysis_stats", {})
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
        except (UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ReputationError("VirusTotal returned an invalid report.") from exc
        verdict = (
            "malicious"
            if malicious > 0
            else "suspicious"
            if suspicious > 0
            else "no_detections"
        )
        result = ReputationResult(
            normalized_type,
            normalized_value,
            "VirusTotal",
            verdict,
            malicious,
            suspicious,
            f"{malicious} malicious and {suspicious} suspicious engine results.",
            datetime.now(UTC).isoformat(),
        )
        self._cache_virustotal(result)
        return result

    def _cached_virustotal(
        self,
        indicator_type: str,
        value: str,
    ) -> ReputationResult | None:
        row = self.database.fetchone(
            "SELECT verdict, malicious, suspicious, detail, checked_at "
            "FROM reputation_cache WHERE provider = 'virustotal' "
            "AND indicator_type = ? AND value = ?",
            (indicator_type, value),
        )
        if row is None:
            return None
        try:
            checked = datetime.fromisoformat(row["checked_at"])
        except (TypeError, ValueError):
            return None
        if datetime.now(UTC) - checked > timedelta(hours=24):
            return None
        return ReputationResult(
            indicator_type,
            value,
            "VirusTotal",
            str(row["verdict"]),
            int(row["malicious"]) if row["malicious"] is not None else None,
            int(row["suspicious"]) if row["suspicious"] is not None else None,
            str(row["detail"]),
            str(row["checked_at"]),
        )

    def _cache_virustotal(self, result: ReputationResult) -> None:
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO reputation_cache "
                "(provider, indicator_type, value, verdict, malicious, suspicious, "
                "detail, checked_at) VALUES ('virustotal', ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(provider, indicator_type, value) DO UPDATE SET "
                "verdict = excluded.verdict, malicious = excluded.malicious, "
                "suspicious = excluded.suspicious, detail = excluded.detail, "
                "checked_at = excluded.checked_at",
                (
                    result.indicator_type,
                    result.value,
                    result.verdict,
                    result.malicious,
                    result.suspicious,
                    result.detail,
                    result.checked_at,
                ),
            )

    def _secret_text(self, name: str) -> str | None:
        secret = self.secret_store.get(name)
        if secret is None:
            return None
        try:
            value = secret.decode("utf-8").strip()
        except UnicodeError as exc:
            raise ReputationError(f"Stored {name} is not valid UTF-8.") from exc
        return value or None

    def _save_secret(self, name: str, value: str) -> None:
        if not isinstance(value, str) or not value.strip() or len(value.strip()) > 512:
            raise ValueError("API credentials must contain between 1 and 512 characters.")
        self.secret_store.set(name, value.strip().encode("utf-8"))


def normalize_url(value: str) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(value.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
        netloc = hostname
        if ":" in hostname and not hostname.startswith("["):
            netloc = f"[{hostname}]"
        if port is not None and not (
            parsed.scheme.lower() == "http" and port == 80
            or parsed.scheme.lower() == "https" and port == 443
        ):
            netloc = f"{netloc}:{port}"
        path = parsed.path or "/"
        normalized = urllib.parse.urlunsplit(
            (parsed.scheme.lower(), netloc, path, parsed.query, "")
        )
    except (UnicodeError, ValueError, AttributeError) as exc:
        raise ValueError("A valid HTTP or HTTPS URL is required.") from exc
    return normalized, hostname


def _parse_urlhaus_csv(content: bytes) -> tuple[tuple[str, str], ...]:
    try:
        text = content.decode("utf-8-sig")
    except UnicodeError as exc:
        raise ReputationError("URLhaus returned a non-UTF-8 feed.") from exc
    rows: list[tuple[str, str]] = []
    reader = csv.reader(line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#"))
    header: list[str] | None = None
    for row in reader:
        if not row:
            continue
        if header is None and "url" in {item.strip().lower() for item in row}:
            header = [item.strip().lower() for item in row]
            continue
        if header is None:
            continue
        if len(row) != len(header):
            continue
        entry = dict(zip(header, row, strict=True))
        url = entry.get("url", "").strip()
        status = entry.get("url_status", "").strip().lower()
        if not url or (status and status != "online"):
            continue
        try:
            normalized, hostname = normalize_url(url)
        except ValueError:
            continue
        rows.append(("url", normalized))
        rows.append(("domain", hostname))
        if len(rows) >= _MAX_FEED_ROWS:
            break
    return tuple(dict.fromkeys(rows))


def _validate_indicator(indicator_type: str, value: str) -> tuple[str, str, str]:
    normalized = value.strip().lower()
    if indicator_type == "sha256":
        if not _SHA256_PATTERN.fullmatch(normalized):
            raise ValueError("VirusTotal file lookups require a valid SHA-256 hash.")
        return "sha256", normalized, f"files/{normalized}"
    if indicator_type == "ip":
        try:
            ipaddress.ip_address(normalized)
        except ValueError as exc:
            raise ValueError("Enter a valid IPv4 or IPv6 address.") from exc
        return "ip", normalized, f"ip_addresses/{normalized}"
    if indicator_type == "domain":
        if not normalized or len(normalized) > 253 or "/" in normalized:
            raise ValueError("Enter a valid domain name.")
        try:
            normalized = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Enter a valid domain name.") from exc
        return "domain", normalized, f"domains/{urllib.parse.quote(normalized, safe='.-')}"
    raise ValueError("VirusTotal lookups support only IP, domain, or SHA-256 indicators.")


def _read_bounded(response, maximum_bytes: int) -> bytes:
    content_length = response.headers.get("Content-Length")
    if content_length is not None:
        try:
            if int(content_length) > maximum_bytes:
                raise ReputationError("The reputation response exceeds the size limit.")
        except ValueError as exc:
            raise ReputationError("The reputation server returned an invalid response length.") from exc
    chunks: list[bytes] = []
    total = 0
    while chunk := response.read(64 * 1024):
        total += len(chunk)
        if total > maximum_bytes:
            raise ReputationError("The reputation response exceeds the size limit.")
        chunks.append(chunk)
    return b"".join(chunks)
