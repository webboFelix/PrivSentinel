from src.security.browser_protection import BrowserProtectionService
from src.security.reputation import ReputationService
from src.storage.database import SQLiteDatabase
from src.storage.repositories.security_repository import SecurityRepository


class MemorySecretStore:
    def contains(self, _name):
        return False

    def get(self, _name):
        return None


def make_service(tmp_path):
    database = SQLiteDatabase(tmp_path / "database.db")
    repository = SecurityRepository(database)
    reputation = ReputationService(database, MemorySecretStore())
    return (
        database,
        BrowserProtectionService(database, reputation, repository),
    )


def test_browser_decision_blocks_local_feed_hit_and_records_private_url(tmp_path):
    database, browser = make_service(tmp_path)
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO reputation_indicators "
            "(provider, indicator_type, value, verdict, first_seen, last_seen) "
            "VALUES ('urlhaus', 'domain', 'malware.example', 'malicious', 'now', 'now')"
        )

    result = browser.evaluate(
        "https://malware.example/download?session=private#fragment",
        "Chrome",
    )

    assert result["action"] == "block"
    row = database.fetchone("SELECT * FROM browser_site_events")
    assert row is not None
    assert row["browser"] == "Chrome"
    assert row["url"] == "https://malware.example/download"
    assert row["decision"] == "blocked"


def test_explicit_user_allow_overrides_feed_block_and_extension_rule(tmp_path):
    database, browser = make_service(tmp_path)
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO reputation_indicators "
            "(provider, indicator_type, value, verdict, first_seen, last_seen) "
            "VALUES ('urlhaus', 'domain', 'malware.example', 'malicious', 'now', 'now')"
        )

    browser.set_domain_decision("malware.example", "allow", "Reviewed false positive")

    result = browser.evaluate("https://sub.malware.example/")
    rules = browser.extension_rules()
    assert result["action"] == "allow"
    assert "malware.example" not in rules["blocked_domains"]
    assert "malware.example" in rules["allowed_domains"]


def test_unknown_site_is_allowed_without_claiming_safety(tmp_path):
    database, browser = make_service(tmp_path)

    result = browser.evaluate("https://ordinary.example/")

    assert result["action"] == "allow"
    assert "not a" in result["detail"]
    row = database.fetchone("SELECT decision FROM browser_site_events")
    assert row["decision"] == "allowed"
