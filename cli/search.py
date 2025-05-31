import os
from pathlib import Path
from whoosh.index import open_dir
from whoosh.qparser import QueryParser
from rich.console import Console
from rich.panel import Panel

# --- Config ---
INDEX_DIR = Path("data/index")
console = Console()

def search_index(query_str):
    if not INDEX_DIR.exists():
        console.print("[bold red]❌ Index not found. Run a scan first.[/bold red]")
        return

    ix = open_dir(INDEX_DIR)
    with ix.searcher() as searcher:
        parser = QueryParser("body", ix.schema)
        query = parser.parse(query_str)
        results = searcher.search(query, limit=10)

        if not results:
            console.print("[yellow]⚠ No matches found.[/yellow]")
        else:
            for hit in results:
                console.print(Panel.fit(
                    f"[bold cyan]{hit['title']}[/bold cyan]\n[green]{hit['url']}[/green]",
                    title="[magenta]Dark Web Match[/magenta]",
                    border_style="cyan"
                ))

if __name__ == "__main__":
    console.print("[bold magenta]Dark Web Search CLI[/bold magenta]")
    while True:
        query = console.input("[bold green]Search[/bold green]> ")
        if query.lower() in ["exit", "quit"]:
            break
        search_index(query)
