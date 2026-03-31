from datetime import datetime, timezone

from dotenv import load_dotenv
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

load_dotenv()

import db
import fetcher
from utils import (
    console,
    parse_affected_software,
    parse_cvss_metrics,
    parse_description,
    parse_references,
    setup_logging,
)


def run_pipeline() -> None:
    logger = setup_logging()

    first_run = db.is_first_run()

    # Startup panel
    # NOTE: full historical CVE load is handled by backfill.py, not main.py.
    # main.py always works on a date window: 30 days on first run, 7 days after.
    days = 30 if first_run else 7
    mode = "[bold red]FIRST RUN — Last 30 Days[/bold red]" if first_run \
           else "[bold cyan]INCREMENTAL — Last 7 Days[/bold cyan]"
    console.print(Panel(mode, title="[bold white] CVEInsight Pipeline[/bold white]",
                        border_style="blue", expand=False))

    # Step 1: Fetch CVEs from NVD with spinner
    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as sp:
        task = sp.add_task(f"Fetching last {days} days of CVEs from NVD...", total=None)
        logger.info(f"{'First' if first_run else 'Incremental'} run — fetching last {days} days")
        raw_cves = fetcher.fetch_cves(days=days)
        sp.update(task, description="Fetch complete")

    total_fetched = len(raw_cves)
    logger.info(f"NVD returned {total_fetched} CVEs")

    if total_fetched == 0:
        logger.info("Nothing to process.")
        return

    # Step 2: Batch check which CVEs already exist
    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as sp:
        sp.add_task("Checking existing CVEs in DB...", total=None)
        all_cve_ids = [c.get("id") for c in raw_cves if c.get("id")]
        existing_ids = db.get_existing_cve_ids(all_cve_ids)

    new_count = total_fetched - len(existing_ids)
    logger.info(f"Already in DB: {len(existing_ids)}  New to insert: {new_count}")

    # Step 3: Parse new CVEs with progress bar
    fetched_at = datetime.now(timezone.utc).isoformat()
    cve_records = []
    all_software = []
    all_ref_rows = []
    cve_software_map = {}
    skipped = 0
    failed = 0

    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                  BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                  console=console) as progress:
        parse_task = progress.add_task("Parsing CVEs...", total=total_fetched)

        for cve in raw_cves:
            cve_id = cve.get("id")
            if not cve_id:
                failed += 1
                progress.advance(parse_task)
                continue

            if cve_id in existing_ids:
                skipped += 1
                progress.advance(parse_task)
                continue

            description = parse_description(cve)
            metrics = parse_cvss_metrics(cve)
            affected_software = parse_affected_software(cve)
            published = cve.get("published", "")[:10] or None
            last_modified = cve.get("lastModified", "")[:10] or None

            cve_records.append({
                "cve_id": cve_id,
                "title": cve_id,
                "description": description,
                "severity": metrics["severity"],
                "cvss_score": metrics["cvss_score"],
                "cvss_vector": metrics["cvss_vector"],
                "attack_vector": metrics["attack_vector"],
                "attack_complexity": metrics["attack_complexity"],
                "privileges_required": metrics["privileges_required"],
                "user_interaction": metrics["user_interaction"],
                "published_at": published,
                "last_modified_at": last_modified,
                "fetched_at": fetched_at,
            })

            cve_software_map[cve_id] = affected_software
            all_software.extend(affected_software)
            cve_software_map[cve_id + "__refs"] = parse_references(cve)
            progress.advance(parse_task)

    parsed_count = len(cve_records)
    logger.info(f"Parsed {parsed_count} new CVEs")

    if parsed_count == 0:
        logger.info("All CVEs already in DB — nothing to insert.")
        _print_summary(total_fetched, 0, skipped, failed, 0, 0)
        return

    # Step 4: Bulk insert CVEs
    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as sp:
        sp.add_task(f"Inserting {parsed_count} CVEs into DB...", total=None)
        uuid_map = db.insert_cves_batch(cve_records)

    inserted = len(uuid_map)
    failed += parsed_count - inserted
    logger.info(f"CVEs inserted: {inserted}")

    # Step 5: Bulk upsert software
    with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as sp:
        sp.add_task(f"Upserting {len(all_software)} software entries...", total=None)
        sw_id_map = db.upsert_software_bulk(all_software)

    # Step 6: Build affected_software + references rows
    affected_rows = []
    for cve_id, uuid in uuid_map.items():
        for sw in cve_software_map.get(cve_id, []):
            key = f"{sw['vendor']}|{sw['product']}"
            if key in sw_id_map:
                affected_rows.append({
                    "cve_id": uuid,
                    "software_id": sw_id_map[key],
                    "version_start": sw.get("version_start"),
                    "version_end": sw.get("version_end"),
                    "fixed_version": sw.get("fixed_version"),
                    "status": "affected",
                })
        for ref in cve_software_map.get(cve_id + "__refs", []):
            all_ref_rows.append({"cve_id": uuid, **ref})

    # Step 7: Bulk insert affected software
    if affected_rows:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as sp:
            sp.add_task(f"Inserting {len(affected_rows)} software links...", total=None)
            db.insert_affected_software_bulk(affected_rows)

    # Step 8: Bulk insert references
    if all_ref_rows:
        with Progress(SpinnerColumn(), TextColumn("[bold blue]{task.description}"),
                      TimeElapsedColumn(), console=console, transient=True) as sp:
            sp.add_task(f"Inserting {len(all_ref_rows)} references...", total=None)
            db.insert_references_bulk(all_ref_rows)

    # Step 9: AI insights for newly inserted CVEs only
    ai_processed = 0
    ai_failed = 0
    if uuid_map:
        logger.info("Generating AI insights for newly inserted CVEs...")
        from ai_step import run_ai_for_cves
        new_cves = [
            {
                "id": uuid_map[r["cve_id"]],
                "cve_id": r["cve_id"],
                "description": r["description"],
                "cvss_score": r["cvss_score"],
                "severity": r["severity"],
                "attack_vector": r["attack_vector"],
            }
            for r in cve_records
            if r["cve_id"] in uuid_map
        ]
        ai_processed, ai_failed = run_ai_for_cves(new_cves)
        logger.info(f"AI insights: {ai_processed} saved, {ai_failed} failed")

    _print_summary(total_fetched, inserted, skipped, failed, ai_processed, ai_failed)


def _print_summary(fetched: int, inserted: int, skipped: int, failed: int,
                   ai_ok: int, ai_fail: int) -> None:
    logger = __import__("logging").getLogger("cveinsight")
    logger.info("=== Pipeline complete ===")

    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 2))
    table.add_column("Metric", style="bold")
    table.add_column("Count", justify="right")
    table.add_row("[blue]Fetched[/blue]",          str(fetched))
    table.add_row("[green]Inserted[/green]",        str(inserted))
    table.add_row("[yellow]Skipped[/yellow]",       str(skipped))
    table.add_row("[red]DB Failed[/red]",           str(failed))
    table.add_row("[green]AI Insights OK[/green]",  str(ai_ok))
    table.add_row("[red]AI Insights Failed[/red]",  str(ai_fail))

    any_failure = failed > 0 or ai_fail > 0
    console.print(Panel(
        table,
        title="[bold white] Pipeline Summary[/bold white]",
        border_style="green" if not any_failure else "yellow",
        expand=False,
    ))


if __name__ == "__main__":
    run_pipeline()
