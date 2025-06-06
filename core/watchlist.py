import json


def load_watchlist(path="data/watchlist.json"):
    with open(path) as f:
        return json.load(f)


def fuzzy_variants(term):
    variants = {term.lower(), term.replace(" ", ""), term.replace(".", "")}
    if "@" in term:
        local, domain = term.split("@")
        variants.add(local + "@" + domain.replace("gmail", "gma1l"))
    return variants


