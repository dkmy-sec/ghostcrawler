import json
from rich import print
from rich.panel import Panel

with open("scrape_data/alerts.json") as f:
    alerts = json.load(f)

if not alerts:
    print("[green]No leaks detected.[/green]")
else:
    for a in alerts:
        print(Panel.fit(
            "\n".join(a["matches"]),
            title=f"[red]LEAK: {a['url']}[/red]",
            border_style="red"
        ))
