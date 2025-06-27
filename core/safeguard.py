BAD_WORDS = {
    "cp", "pthc", "preteen", "hardcore cp", "11-yo", "underage", "zoophilia", "porn-chile-links"
    "babyj", "kidporn", "childporn", "loli", "kid", "small-girl", "teens", "hannah-f-candydoll"
}

def is_high_risk(url: str, html: str) -> bool:
    url_l = url.lower()
    if any(w in url_l for w in BAD_WORDS):
        return True
    text = html.lower()
    if any(w in text for w in BAD_WORDS):
        return True
    return False
