"""Local website decisions shared by browser connectors and the desktop UI."""

from __future__ import annotations

from datetime import UTC, datetime

from src.security.reputation import ReputationService, normalize_url
from src.storage.database import SQLiteDatabase
from src.storage.repositories.security_repository import SecurityRepository


class BrowserProtectionService:
    def __init__(
        self,
        database: SQLiteDatabase,
        reputation: ReputationService,
        security_repository: SecurityRepository,
    ) -> None:
        self.database = database
        self.reputation = reputation
        self.security_repository = security_repository

    def evaluate(self, url: str, browser: str = "browser") -> dict[str, str]:
        normalized_url, domain = normalize_url(url)
        decision_row = self._domain_decision(domain)
        if decision_row is not None:
            action = str(decision_row["decision"])
            provider = "user decision"
            detail = str(decision_row["reason"])
        else:
            urlhaus_result = self.reputation.check_urlhaus(normalized_url)
            if urlhaus_result is not None:
                action = "block"
                provider = "URLhaus"
                detail = urlhaus_result.detail
            elif self._has_local_domain_indicator(domain):
                action = "block"
                provider = "local analyst indicator"
                detail = "The domain matches a locally maintained block indicator."
            else:
                cached = self.database.fetchone(
                    "SELECT verdict, malicious, suspicious FROM reputation_cache "
                    "WHERE provider = 'virustotal' AND indicator_type = 'domain' "
                    "AND value = ?",
                    (domain,),
                )
                if cached is not None and cached["verdict"] == "malicious":
                    action = "block"
                    provider = "VirusTotal cached reputation"
                    detail = (
                        f"{cached['malicious']} VirusTotal engines reported this "
                        "domain as malicious."
                    )
                elif cached is not None and cached["verdict"] == "suspicious":
                    action = "review"
                    provider = "VirusTotal cached reputation"
                    detail = (
                        f"{cached['suspicious']} VirusTotal engines reported this "
                        "domain as suspicious; review before trusting it."
                    )
                else:
                    action = "allow"
                    provider = "no local match"
                    detail = (
                        "No local malicious indicator matched. This is not a "
                        "reputation verdict or a guarantee that the site is safe."
                    )

        recorded_decision = {
            "allow": "allowed",
            "block": "blocked",
            "review": "matched",
        }[action]
        safe_url = _url_without_query(normalized_url)
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO browser_site_events "
                "(occurred_at, browser, url, domain, decision, provider, detail) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(UTC).isoformat(),
                    browser[:40],
                    safe_url[:2048],
                    domain[:253],
                    recorded_decision,
                    provider[:80],
                    detail[:1000],
                ),
            )
        return {
            "action": action,
            "domain": domain,
            "provider": provider,
            "detail": detail,
        }

    def set_domain_decision(
        self,
        domain: str,
        decision: str,
        reason: str = "User decision",
    ) -> None:
        normalized = _normalize_domain(domain)
        if decision not in {"allow", "block"}:
            raise ValueError("Website decisions must be allow or block.")
        timestamp = datetime.now(UTC).isoformat()
        with self.database.transaction() as connection:
            connection.execute(
                "INSERT INTO browser_domain_decisions "
                "(domain, decision, reason, updated_at) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(domain) DO UPDATE SET decision = excluded.decision, "
                "reason = excluded.reason, updated_at = excluded.updated_at",
                (normalized, decision, reason.strip()[:500], timestamp),
            )
        self.security_repository.record_audit(
            "user",
            f"browser.domain_{decision}",
            "success",
            f"{normalized}: {reason.strip()[:500]}",
        )

    def list_site_events(self, limit: int = 1000) -> list[dict[str, object]]:
        if not 1 <= limit <= 10000:
            raise ValueError("Website event limit must be between 1 and 10000.")
        return [
            dict(row)
            for row in self.database.fetchall(
                "SELECT * FROM browser_site_events ORDER BY occurred_at DESC LIMIT ?",
                (limit,),
            )
        ]

    def list_domain_decisions(self) -> list[dict[str, object]]:
        return [
            dict(row)
            for row in self.database.fetchall(
                "SELECT * FROM browser_domain_decisions ORDER BY updated_at DESC"
            )
        ]

    def extension_rules(self, limit: int = 2000) -> dict[str, list[str]]:
        if not 1 <= limit <= 5000:
            raise ValueError("Browser rule limit must be between 1 and 5000.")
        blocked: set[str] = set()
        review: set[str] = set()
        for row in self.database.fetchall(
            "SELECT value FROM reputation_indicators "
            "WHERE provider = 'urlhaus' AND indicator_type = 'domain' "
            "ORDER BY last_seen DESC LIMIT ?",
            (limit,),
        ):
            blocked.add(str(row["value"]))
        for row in self.database.fetchall(
            "SELECT value FROM threat_indicators WHERE indicator_type = 'domain' "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ):
            blocked.add(_normalize_domain(str(row["value"])))
        for row in self.database.fetchall(
            "SELECT value, verdict FROM reputation_cache WHERE provider = 'virustotal' "
            "AND indicator_type = 'domain' "
            "AND verdict IN ('malicious', 'suspicious') "
            "ORDER BY checked_at DESC LIMIT ?",
            (limit,),
        ):
            if row["verdict"] == "malicious":
                blocked.add(str(row["value"]))
            else:
                review.add(str(row["value"]))
        allowed = {
            str(row["domain"])
            for row in self.database.fetchall(
                "SELECT domain FROM browser_domain_decisions WHERE decision = 'allow'"
            )
        }
        user_blocked = {
            str(row["domain"])
            for row in self.database.fetchall(
                "SELECT domain FROM browser_domain_decisions WHERE decision = 'block'"
            )
        }
        blocked.difference_update(allowed)
        blocked.update(user_blocked)
        review.difference_update(blocked | allowed)
        return {
            "blocked_domains": sorted(blocked)[: min(limit, 1000)],
            "allowed_domains": sorted(allowed)[: min(limit, 500)],
            "review_domains": sorted(review)[: min(limit, 500)],
        }

    def _domain_decision(self, domain: str):
        rows = self.database.fetchall(
            "SELECT domain, decision, reason FROM browser_domain_decisions"
        )
        matches = [
            row
            for row in rows
            if domain == row["domain"] or domain.endswith(f".{row['domain']}")
        ]
        return max(matches, key=lambda row: len(str(row["domain"])), default=None)

    def _has_local_domain_indicator(self, domain: str) -> bool:
        indicators = self.database.fetchall(
            "SELECT value FROM threat_indicators WHERE indicator_type = 'domain'"
        )
        return any(
            domain == str(row["value"]).lower()
            or domain.endswith(f".{str(row['value']).lower()}")
            for row in indicators
        )


def _normalize_domain(value: str) -> str:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith(("http://", "https://")):
        _normalized, candidate = normalize_url(candidate)
    if not candidate or len(candidate) > 253 or "/" in candidate:
        raise ValueError("Enter a valid domain name.")
    try:
        return candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Enter a valid domain name.") from exc


def _url_without_query(url: str) -> str:
    scheme, separator, remainder = url.partition("://")
    if not separator:
        return url
    authority, slash, path = remainder.partition("/")
    safe_path = path.partition("?")[0].partition("#")[0]
    return f"{scheme}://{authority}{slash}{safe_path}"
