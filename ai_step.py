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
AI_BATCH           = 5    # CVEs per single API call (lower = fewer tokens)
RATE_DELAY         = 12   # seconds between API calls (Groq free tier: ~30 RPM)
START_YEAR         = datetime.now().year
END_YEAR           = 2017
MAX_CONSEC_FAILS   = 5    # stop a year if this many consecutive batches all fail
MAX_GLOBAL_FAILS   = 3    # stop the entire run if both providers fail 3 times in a row


def run_ai_for_batch(batch: list) -> tuple[int, int, set]:
    """
    Process ONE AI batch (up to AI_BATCH CVEs) through Groq/Gemini.
    Each dict must have: id, cve_id, description, cvss_score, severity, attack_vector.
    Returns (processed, failed, processed_ids).
    """
    logger = logging.getLogger("cveinsight")
    processed = 0
    failed = 0
    processed_ids: set = set()

    results, model_used = generate_insights_batch(batch)

    for cve in batch:
        insights = results.get(cve["cve_id"])
        if insights:
            db.insert_ai_insights(cve["id"], insights, model_used)
            processed_ids.add(cve["id"])
            processed += 1
            logger.info(f"Saved: {cve['cve_id']} (via {model_used})")
        else:
            failed += 1
            logger.warning(f"Failed: {cve['cve_id']}")

    return processed, failed, processed_ids


def run_ai_step() -> None:
    logger = setup_logging()

    console.print(Panel(
        f"AI insights backfill  [bold]{START_YEAR} → {END_YEAR}[/bold]\n"
        f"{AI_BATCH} CVEs per API call  |  {RATE_DELAY}s between calls\n"
        f"[dim]Providers: Groq (primary) → Gemini (fallback)[/dim]",
        title="[bold white] CVEInsight — AI Backfill[/bold white]",
        border_style="blue",
        expand=False,
    ))

    total_processed = 0
    total_failed = 0
    global_consec_fails = 0   # across all years — if both providers are down, stop entirely
    abort = False

    # Load done_ids ONCE before the year loop — avoids a full DB scan every year.
    # We update this set in-memory as we process each CVE.
    done_ids = db.get_all_insight_cve_ids()
    logger.info(f"Already have insights for {len(done_ids)} CVEs total")

    for year in range(START_YEAR, END_YEAR - 1, -1):
        if abort:
            break

        logger.info(f"--- Year {year} ---")

        year_processed    = 0
        offset            = 0
        consec_fail_batches = 0  # consecutive batches within this year

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Year {year} — starting...", total=None)

            stop_year = False
            while not stop_year:
                # Fetch raw page from DB without pre-filtering.
                # We filter locally so offset advances by actual DB rows,
                # not filtered count — prevents skipping rows.
                raw_page = db.get_cves_for_year(year, FETCH_BATCH, offset)

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

                # Process in AI_BATCH chunks so failure counters tick per API call,
                # not per page — enables fast abort when both providers are down.
                batches = [cves[i: i + AI_BATCH] for i in range(0, len(cves), AI_BATCH)]
                for batch_idx, batch in enumerate(batches):
                    p, f, saved_ids = run_ai_for_batch(batch)
                    year_processed  += p
                    total_processed += p
                    total_failed    += f

                    # Track consecutive failures per API call — globally and per year
                    if p == 0 and f > 0:
                        consec_fail_batches += 1
                        global_consec_fails += 1

                        if global_consec_fails >= MAX_GLOBAL_FAILS:
                            logger.error(
                                f"Both Groq and Gemini failed {MAX_GLOBAL_FAILS} API calls in a row — "
                                f"quota likely exhausted or API keys invalid. Exiting."
                            )
                            abort = True
                            stop_year = True
                            break

                        if consec_fail_batches >= MAX_CONSEC_FAILS:
                            logger.error(
                                f"Year {year}: {MAX_CONSEC_FAILS} consecutive batches all failed — "
                                f"skipping to next year."
                            )
                            stop_year = True
                            break
                    else:
                        consec_fail_batches = 0
                        global_consec_fails = 0  # reset only on success

                    progress.update(task, description=(
                        f"Year {year} — {year_processed} done  "
                        f"[green]✓{total_processed}[/green]  [red]✗{total_failed}[/red]"
                    ))

                    # Only mark successfully saved CVEs as done — failed ones stay
                    # eligible for retry if the AI provider recovers later in this run.
                    done_ids.update(saved_ids)

                    # Sleep between batches but not after the last one in the page
                    if batch_idx < len(batches) - 1 and not stop_year:
                        time.sleep(RATE_DELAY)

        logger.info(f"Year {year} complete — {year_processed} insights added")

    logger.info("=== AI Backfill Complete ===")
    logger.info(f"  Total processed : {total_processed}")
    logger.info(f"  Total failed    : {total_failed}")


if __name__ == "__main__":
    run_ai_step()
