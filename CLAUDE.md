# CVEInsight — Claude Code Context

## Project Overview
CVEInsight is a cybersecurity vulnerability platform that fetches CVE data from
the National Vulnerability Database (NVD), enriches it with AI-generated plain
English explanations using Gemini, and stores everything in Supabase. The React
frontend (built separately) reads directly from Supabase.

This repo contains ONLY the backend data pipeline. No frontend code here.

---

## Repo Structure (build this exactly)
```
cveinsight-script/
├── CLAUDE.md                    ← this file
├── README.md
├── requirements.txt
├── .env                         ← never commit this
├── .gitignore
├── main.py                      ← entry point, runs full pipeline once
├── scheduler.py                 ← runs main.py every 6 hours
├── fetcher.py                   ← hits NVD API, returns raw CVE data
├── ai_processor.py              ← sends CVE to Gemini, returns insights
├── db.py                        ← all Supabase read/write operations
├── utils.py                     ← shared helpers (logging, parsing)
└── .github/
    └── workflows/
        └── fetch_cves.yml       ← GitHub Actions scheduler (every 6 hours)
```

---

## Tech Stack
- **Language**: Python 3.11+
- **Database**: Supabase (PostgreSQL under the hood)
- **Supabase client**: `supabase-py`
- **NVD API**: REST, v2, no auth needed but API key removes rate limits
- **AI**: Google Gemini 1.5 Flash (free tier) via `google-generativeai`
- **Scheduler**: GitHub Actions (free, runs every 6 hours)
- **HTTP**: `httpx` (async-friendly, better than requests)
- **Env vars**: `python-dotenv`

---

## Supabase Schema (already created — do not recreate)

### Table: `cves`
```sql
id uuid PK
cve_id text UNIQUE          -- e.g. "CVE-2024-12345"
title text
description text
severity text               -- CRITICAL / HIGH / MEDIUM / LOW / NONE
cvss_score float
cvss_vector text
attack_vector text
attack_complexity text
privileges_required text
user_interaction text
published_at date
last_modified_at date
fetched_at timestamp
created_at timestamp
```

### Table: `software`
```sql
id uuid PK
vendor text
product text
ecosystem text
created_at timestamp
UNIQUE(vendor, product)     -- no duplicates
```

### Table: `cve_affected_software`
```sql
id uuid PK
cve_id uuid FK → cves.id
software_id uuid FK → software.id
version_start text
version_end text
fixed_version text
status text                 -- default 'affected'
```

### Table: `cve_references`
```sql
id uuid PK
cve_id uuid FK → cves.id
url text
source text
tag text
```

### Table: `cve_ai_insights`
```sql
id uuid PK
cve_id uuid FK → cves.id
plain_english text          -- what this CVE means in simple words
fix_steps text              -- step by step how to fix it
risk_summary text           -- one line risk summary
model_used text             -- default 'gemini-1.5-flash'
generated_at timestamp
```

### Table: `cve_relations`
```sql
id uuid PK
cve_id uuid FK → cves.id
related_cve_id uuid FK → cves.id
relation_type text          -- 'same_software' | 'same_vendor' | 'similar_cvss'
UNIQUE(cve_id, related_cve_id)
```

---

## Environment Variables (never commit .env)
```
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=your_service_role_key
NVD_API_KEY=your_nvd_api_key
GEMINI_API_KEY=your_gemini_api_key
```

For GitHub Actions, all 4 go into repo Settings → Secrets → Actions.

---

## NVD API Details
- Base URL: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- Key params:
  - `resultsPerPage` → max 2000
  - `startIndex` → for pagination
  - `pubStartDate` / `pubEndDate` → filter by date (ISO 8601)
  - `lastModStartDate` / `lastModEndDate` → fetch only updated CVEs
- Rate limit without key: 5 requests per 30 seconds
- Rate limit with key: 50 requests per 30 seconds
- Always add `apiKey` header if NVD_API_KEY is set
- Add 1 second sleep between paginated requests to be safe
- NVD returns data in `vulnerabilities[].cve` structure

### NVD Response Shape (important)
```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2024-12345",
        "descriptions": [{"lang": "en", "value": "..."}],
        "published": "2024-01-15T10:00:00.000",
        "lastModified": "2024-01-20T12:00:00.000",
        "metrics": {
          "cvssMetricV31": [{
            "cvssData": {
              "baseScore": 9.8,
              "baseSeverity": "CRITICAL",
              "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
              "attackVector": "NETWORK",
              "attackComplexity": "LOW",
              "privilegesRequired": "NONE",
              "userInteraction": "NONE"
            }
          }]
        },
        "configurations": [...],
        "references": [{"url": "...", "source": "...", "tags": [...]}]
      }
    }
  ]
}
```

---

## Pipeline Flow (main.py runs this in order)

```
1. fetcher.py   → fetch last 7 days of CVEs from NVD (paginated)
2. db.py        → for each CVE, check if cve_id already exists (skip if yes)
3. db.py        → insert into cves table
4. db.py        → upsert software into software table, get software.id
5. db.py        → insert into cve_affected_software
6. db.py        → insert into cve_references
7. ai_processor.py → generate plain_english + fix_steps + risk_summary
8. db.py        → insert into cve_ai_insights
9. db.py        → compute and insert cve_relations (same software)
10. utils.py    → log summary: X inserted, Y skipped, Z failed
```

---

## AI Processor — Gemini Prompt Pattern

Send this to Gemini for each CVE:

```
You are a cybersecurity expert. Given this CVE data, respond ONLY in JSON.

CVE ID: {cve_id}
Description: {description}
CVSS Score: {cvss_score}
Severity: {severity}
Attack Vector: {attack_vector}

Return exactly this JSON structure:
{
  "plain_english": "2-3 sentence explanation a developer can understand",
  "fix_steps": "numbered steps to fix or mitigate this vulnerability",
  "risk_summary": "one sentence: who is at risk and how serious"
}
```

Parse the JSON response and store each field separately in `cve_ai_insights`.
If Gemini fails or returns invalid JSON, store null for that CVE and log the error.
Never crash the pipeline because of one AI failure.

---

## Error Handling Rules
- If NVD API returns 403 → log and stop (API key issue)
- If NVD API returns 503 → wait 60 seconds, retry once
- If a single CVE insert fails → log it, skip it, continue pipeline
- If Gemini fails for a CVE → insert CVE anyway, leave ai_insights null
- If Supabase insert fails → log full error with cve_id, continue
- Never let one bad CVE crash the whole run
- At the end of every run, print a summary: total fetched / inserted / skipped / failed

---

## GitHub Actions Schedule
File: `.github/workflows/fetch_cves.yml`
- Trigger: `schedule` cron `0 */6 * * *` (every 6 hours)
- Also trigger: `workflow_dispatch` (manual run button)
- Runner: `ubuntu-latest`
- Python version: `3.11`
- Steps: checkout → setup python → install requirements → run `python main.py`
- Secrets used: `SUPABASE_URL`, `SUPABASE_SERVICE_KEY`, `NVD_API_KEY`, `GEMINI_API_KEY`

---

## Key Rules for Claude Code
- Use `supabase-py` client, not raw SQL or REST calls
- Use `httpx` for all HTTP requests, not `requests`
- Always use `python-dotenv` to load `.env`
- All Supabase operations go in `db.py` only — other files import from db.py
- All NVD fetch logic goes in `fetcher.py` only
- All Gemini logic goes in `ai_processor.py` only
- `main.py` just orchestrates — it imports and calls the others
- Log every major step with timestamp using Python `logging` module
- On first run, fetch last 30 days of CVEs to populate the DB
- On subsequent runs, fetch only last 7 days (incremental updates)
- Check if CVE already exists before inserting (use cve_id unique constraint)
- After inserting a batch, log how many were new vs skipped

---

## Do Not
- Do not use `requests` library (use `httpx`)
- Do not hardcode any API keys or URLs
- Do not commit `.env` file
- Do not recreate Supabase tables (schema already exists)
- Do not call Gemini for CVEs that already have ai_insights
- Do not fetch all CVEs from the beginning every run (too slow, hits rate limits)
- Do not use `print()` for logging (use Python `logging` module)
