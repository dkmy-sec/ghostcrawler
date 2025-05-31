import re
from core.watchlist import fuzzy_variants

# Precompiled regex patterns
PATTERNS = {
    "CREDIT_CARD_REGEX": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "SSN_REGEX": re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
}

def confidence_score(match: str, original: str) -> int:
    """Basic scoring by how similar the match is to the original"""
    match = match.lower().replace(" ", "").replace("-", "")
    original = original.lower().replace(" ", "").replace("-", "")
    return int((len(set(match) & set(original)) / len(original)) * 100)

def scan(html: str, watchlist: dict) -> list:
    """
    Scan HTML for exact/fuzzy matches, regex patterns, and return alerts with confidence scores.
    """
    matches = []
    html_lower = html.lower()

    # 1. Watchlist Fuzzy Matching
    for field, items in watchlist.items():
        for item in items:
            for variant in fuzzy_variants(item):
                if variant.lower() in html_lower:
                    score = confidence_score(variant, item)
                    matches.append(f"{field.upper()} match: '{variant}' (confidence: {score}%)")

    # 2. Regex Matching
    for match in PATTERNS["SSN_REGEX"].findall(html):
        matches.append(f"SSN pattern detected: {match} (regex)")

    for match in PATTERNS["CREDIT_CARD_REGEX"].findall(html):
        clean = re.sub(r"[ -]", "", match)
        if len(clean) in [13, 14, 15, 16]:
            matches.append(f"CREDIT_CARD pattern detected: {match} (regex)")

    return matches
hes
