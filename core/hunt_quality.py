from __future__ import annotations

import re


NON_WORD_RE = re.compile(r"[^a-z0-9]+")
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
WALLET_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,62}\b")


def normalize_text(value: str | None) -> str:
    lowered = (value or "").strip().lower()
    lowered = lowered.replace("[.]", ".").replace("(dot)", ".").replace(" dot ", ".")
    lowered = lowered.replace("[at]", "@").replace("(at)", "@").replace(" at ", "@")
    return lowered


def compact_text(value: str | None) -> str:
    return NON_WORD_RE.sub("", normalize_text(value))


def normalized_variants(value: str | None) -> set[str]:
    normalized = normalize_text(value)
    compact = compact_text(value)
    variants = {normalized, compact}

    if "@" in normalized:
        local, _, domain = normalized.partition("@")
        variants.update({domain, compact_text(domain), local})

    if "." in normalized:
        variants.add(normalized.replace(".", ""))

    return {item for item in variants if item}


def extract_entities(text: str | None) -> dict[str, set[str]]:
    normalized = normalize_text(text)
    return {
        "emails": {normalize_text(match.group(0)) for match in EMAIL_RE.finditer(normalized)},
        "domains": {normalize_text(match.group(0)) for match in DOMAIN_RE.finditer(normalized)},
        "cves": {normalize_text(match.group(0)) for match in CVE_RE.finditer(normalized)},
        "wallets": {normalize_text(match.group(0)) for match in WALLET_RE.finditer(normalized)},
    }


def dedupe_records(records: list[dict], keys: list[str]) -> list[dict]:
    seen = set()
    unique = []
    for record in records:
        fingerprint = tuple((record.get(key) or "") for key in keys)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(record)
    return unique


def score_match(indicator_type: str, needle: str, haystack: str, entities: dict[str, set[str]], fuzzy: bool) -> tuple[bool, int]:
    normalized_needle = normalize_text(needle)
    compact_needle = compact_text(needle)
    normalized_haystack = normalize_text(haystack)
    compact_haystack = compact_text(haystack)

    entity_key = {
        "email": "emails",
        "domain": "domains",
        "cve": "cves",
        "wallet": "wallets",
    }.get((indicator_type or "keyword").lower())

    if entity_key:
        if normalized_needle in entities.get(entity_key, set()):
            return True, 96
        if fuzzy and compact_needle in {compact_text(item) for item in entities.get(entity_key, set())}:
            return True, 88

    if normalized_needle and normalized_needle in normalized_haystack:
        return True, 84
    if compact_needle and compact_needle in compact_haystack:
        return True, 78 if fuzzy else 72
    return False, 0
