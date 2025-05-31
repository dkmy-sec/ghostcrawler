from core.identity import rotate_identity
from core.watchlist import load_watchlist
from core.search_engine import get_ahmia_results

def crawl_pages(url, watchlist):
    print(f'Crawling: {url}')

if __name__ == '__main__':
    watchlist = load_watchlist()
    targets = get_ahmia_results(' '.join(watchlist.get('emails', [])))
    print(f'[+] Loaded {len(targets)} targets from Ahmia.')
    for i, target in enumerate(targets):
        print(f'[{i+1}/{len(targets)}] {target}')
        crawl_pages(target, watchlist)
        if i % 5 == 0:
            rotate_identity()
