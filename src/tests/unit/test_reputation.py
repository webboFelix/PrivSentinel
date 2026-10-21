import json

import pytest

from src.security.reputation import (
    ReputationError,
    ReputationService,
    normalize_url,
)
from src.storage.database import SQLiteDatabase


class MemorySecretStore:
    def __init__(self):
        self.values = {}

    def set(self, name, value):
        self.values[name] = value

    def get(self, name):
        return self.values.get(name)

    def contains(self, name):
        return name in self.values

    def delete(self, name):
        return self.values.pop(name, None) is not None


class FakeResponse:
    def __init__(self, body):
        self.body = body
        self.headers = {"Content-Length": str(len(body))}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, size):
        body, self.body = self.body[:size], self.body[size:]
        return body


def test_urlhaus_feed_sync_imports_active_urls_and_domains(tmp_path, monkeypatch):
    database = SQLiteDatabase(tmp_path / "database.db")
    secrets = MemorySecretStore()
    service = ReputationService(database, secrets)
    service.save_urlhaus_key("test-auth-key")
    feed = (
        b"id,dateadded,url,url_status,threat,tags\n"
        b'1,2026-10-01,"https://evil.example/path",online,malware_download,test\n'
        b'2,2026-10-01,"https://offline.example/",offline,malware_download,test\n'
    )
    captured_request = []

    def fake_urlopen(request, timeout):
        captured_request.append((request.full_url, timeout))
        return FakeResponse(feed)

    monkeypatch.setattr("src.security.reputation.urllib.request.urlopen", fake_urlopen)

    count = service.sync_urlhaus()

    assert count == 2
    assert "test-auth-key" in captured_request[0][0]
    matched = service.check_urlhaus("https://evil.example/another")
    assert matched is not None
    assert matched.verdict == "malicious"
    assert service.check_urlhaus("https://offline.example/") is None


def test_virus_total_lookup_validates_hash_and_caches_result(tmp_path, monkeypatch):
    database = SQLiteDatabase(tmp_path / "database.db")
    secrets = MemorySecretStore()
    service = ReputationService(database, secrets)
    service.save_virustotal_key("api-secret")
    payload = json.dumps(
        {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 3, "suspicious": 1}
                }
            }
        }
    ).encode()
    calls = []

    def fake_urlopen(request, timeout):
        calls.append(request)
        return FakeResponse(payload)

    monkeypatch.setattr("src.security.reputation.urllib.request.urlopen", fake_urlopen)
    digest = "a" * 64

    result = service.lookup_virustotal("sha256", digest)
    cached = service.lookup_virustotal("sha256", digest)

    assert result.verdict == "malicious"
    assert result.malicious == 3
    assert cached == result
    assert len(calls) == 1
    assert calls[0].get_header("X-apikey") == "api-secret"
    with pytest.raises(ValueError, match="SHA-256"):
        service.lookup_virustotal("sha256", "not-a-hash")


def test_bad_urlhaus_feed_does_not_replace_previous_indicators(tmp_path, monkeypatch):
    database = SQLiteDatabase(tmp_path / "database.db")
    secrets = MemorySecretStore()
    service = ReputationService(database, secrets)
    service.save_urlhaus_key("test-auth-key")
    with database.transaction() as connection:
        connection.execute(
            "INSERT INTO reputation_indicators "
            "(provider, indicator_type, value, verdict, first_seen, last_seen) "
            "VALUES ('urlhaus', 'domain', 'known.example', 'malicious', 'now', 'now')"
        )
    monkeypatch.setattr(
        "src.security.reputation.urllib.request.urlopen",
        lambda *_args, **_kwargs: FakeResponse(b"# invalid or empty feed\n"),
    )

    with pytest.raises(ReputationError, match="existing feed was kept"):
        service.sync_urlhaus()
    assert service.check_urlhaus("https://known.example/") is not None


def test_url_normalization_removes_default_port_and_fragment():
    normalized, hostname = normalize_url("HTTPS://Example.COM:443/path?q=1#section")
    assert normalized == "https://example.com/path?q=1"
    assert hostname == "example.com"


def test_url_normalization_rejects_non_http_schemes():
    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        normalize_url("file:///C:/secret.txt")
