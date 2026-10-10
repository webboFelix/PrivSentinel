"""Deduplication key generation for event alerts."""

import hashlib

from src.core.event_models import SecurityEvent


def deduplication_key(rule_id: str, event: SecurityEvent) -> str:
    basis = "\0".join(
        (
            rule_id,
            event.source,
            event.event_type,
            str(event.attributes.get("process_name", "")),
            str(event.attributes.get("path", "")),
            str(event.attributes.get("remote_address", "")),
        )
    )
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()