from __future__ import annotations


def fuzzy_variants(value: str) -> set[str]:
    cleaned = (value or "").strip()
    if not cleaned:
        return set()

    lowered = cleaned.lower()
    compact = lowered.replace(" ", "").replace("-", "").replace("_", "")
    dashed = lowered.replace(" ", "-").replace("_", "-")
    underscored = lowered.replace(" ", "_").replace("-", "_")

    variants = {cleaned, lowered, compact, dashed, underscored}

    if "@" in lowered:
        local_part, _, domain = lowered.partition("@")
        variants.add(f"{local_part} [at] {domain}")
        variants.add(f"{local_part}(at){domain}")
        variants.add(f"{local_part} at {domain}")

    if "." in lowered:
        variants.add(lowered.replace(".", "[.]"))
        variants.add(lowered.replace(".", " dot "))

    return {item for item in variants if item}
