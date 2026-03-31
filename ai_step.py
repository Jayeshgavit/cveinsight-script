import logging
import time
from datetime import datetime

from dotenv import load_dotenv
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

load_dotenv()

import db
from ai_processor import generate_insights_batch
from utils import console, setup_logging

FETCH_BATCH        = 100  # CVEs fetched from DB per round
AI_BATCH           = 5    # CVEs per single Groq API call (lower = fewer tokens)
RATE_DELAY         = 12   # seconds between API calls (Groq free tier: ~30 RPM)
START_YEAR         = datetime.now().year
END_YEAR           = 1999
MAX_CONSEC_FAILS   = 5    # stop a year if this many consecutive batches all fail


def run_ai_for_cves(cves: list) -> tuple[int, int]:
    """
    Process CVEs through Groq in batches of AI_BATCH.
    Each dict must have: id, cve_id, description, cvss_score, severity, attack_vector.
    Returns (processed, failed).
    """
    logger = logging.getLogger("cveinsight")
    processed = 0
    failed = 0

    batches = [cves[i: i + AI_BATCH] for i in range(0, len(cves), AI_BATCH)]

    for idx, batch in enumerate(batches):
        results = generate_insights_batch(batch)  # 1 API call for up to AI_BATCH CVEs

        for cve in batch:
            insights = results.get(cve["cve_id"])
            if insights:
                db.insert_ai_insights(cve["id"], insights)
                processed += 1
                logger.info(f"Saved: {cve['cve_id']}")
            else:
                failed += 1
                logger.warning(f"Failed: {cve['cve_id']}")

        # Don't sleep after the last batch
        if idx < len(batches) - 1:
            time.sleep(RATE_DELAY)

    return processed, failed


def run_ai_step() -> None:
    logger = setup_logging()

    console.print(Panel(
        f"AI insights backfill  [bold]{START_YEAR} → {END_YEAR}[/bold]\n"
        f"{AI_BATCH} CVEs per API call  |  {RATE_DELAY}s between calls",
        title="[bold white] CVEInsight — AI Backfill[/bold white]",
        border_style="blue",
        expand=False,
    ))

    total_processed = 0
    total_failed = 0

    # Load done_ids ONCE before the year loop — avoids a full DB scan every year.
    # We update this set in-memory as we process each CVE.
    done_ids = db.get_all_insight_cve_ids()
    logger.info(f"Already have insights for {len(done_ids)} CVEs total")

    for year in range(START_YEAR, END_YEAR - 1, -1):
        logger.info(f"--- Year {year} ---")

        year_processed    = 0
        offset            = 0
        consec_fail_batches = 0  # consecutive batches where Groq returned nothing

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Year {year} — starting...", total=None)

            while True:
                # Fetch raw page from DB without filtering (pass empty set).
                # We filter locally so we can correctly advance the offset
                # even when the whole page is already done.
                raw_page = db.get_cves_for_year(year, set(), FETCH_BATCH, offset)

                if not raw_page:
                    # Truly no more rows in DB for this year — we're done.
                    break

                # Advance offset by actual DB rows returned, not by AI processed count.
                # This prevents the early-break bug when a full page is already done.
                offset += len(raw_page)

                # Filter out CVEs that already have insights
                cves = [c for c in raw_page if c["id"] not in done_ids]

                if not cves:
                    # This DB page was all already done — keep going to next page.
                    continue

                p, f = run_ai_for_cves(cves)
                year_processed  += p
                total_processed += p
                total_failed    += f

                # Track consecutive total-failure batches to detect Groq outages
                if p == 0 and f > 0:
                    consec_fail_batches += 1
                    if consec_fail_batches >= MAX_CONSEC_FAILS:
                        logger.error(
                            f"Year {year}: {MAX_CONSEC_FAILS} consecutive batches all failed — "
                            f"Groq may be down. Stopping this year to avoid wasting quota."
                        )
                        break
                else:
                    consec_fail_batches = 0

                progress.update(task, description=(
                    f"Year {year} — {year_processed} done  "
                    f"[green]✓{total_processed}[/green]  [red]✗{total_failed}[/red]"
                ))

                # Add processed CVEs to done_ids so future pages skip them
                for cve in cves:
                    done_ids.add(cve["id"])

        logger.info(f"Year {year} complete — {year_processed} insights added")

    logger.info("=== AI Backfill Complete ===")
    logger.info(f"  Total processed : {total_processed}")
    logger.info(f"  Total failed    : {total_failed}")


if __name__ == "__main__":
    run_ai_step()
