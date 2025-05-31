def get_ahmia_results(query):
    import requests, re
    r = requests.get(f"https://ahmia.fi/search/?q={query}")
    return list(set(re.findall(r'http[s]?://[a-zA-Z0-9\.]*\.onion', r.text)))
