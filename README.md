# ReconIQ

### Cybersecurity Investigation Platform

**Evidence. Intelligence. Trust.**

ReconIQ investigates suspicious content — pasted text, emails, PDFs, screenshots and QR codes, Android apps or any
binary — and produces an explainable risk assessment. A **deterministic-first pipeline** extracts and validates
indicators, enriches them with threat intelligence, and scores them with a transparent rule engine mapped to MITRE
ATT&CK. An AI analyst then explains the result in plain language.

> **Core principle — AI never decides whether something is malicious.**
> Scores, severities and classifications come only from fixed, auditable rules. The AI analyst runs *after* scoring,
> reads a snapshot of the finished assessment, writes to a separate field, and cannot change the verdict.

---

## Features

| Area | What ReconIQ does |
|---|---|
| **Ingestion** | Text (defanged notation supported), `.eml` emails, PDFs, images (QR decoding, optional OCR), Android APKs, text/log files, and any binary (fingerprint + hash lookup). |
| **Indicators** | IPv4/IPv6, URLs (including IP-literal hosts), domains, emails, phone numbers and MD5/SHA-1/SHA-256 hashes — refanged, normalized and validated (RFC checks, TLDs, private/reserved ranges). |
| **Email analysis** | SPF/DKIM/DMARC verdicts, display name, reply-to and return-path routing, relay IPs, HTML link targets, attachment fingerprints. |
| **File analysis** | Magic-byte typing, hashes, dangerous-type and extension-mismatch detection, PDF links and active content (`/JavaScript`, `/OpenAction`, `/Launch`…), APK package, permissions and embedded URLs. |
| **Threat intelligence** | VirusTotal, AbuseIPDB, URLhaus, Google Safe Browsing, Have I Been Pwned (key-based) and Shodan InternetDB and RDAP domain age (keyless). Concurrent, cached and rate-limited, with graceful degradation. |
| **Risk engine** | 27 deterministic rules → 0–100 score, severity, confidence, primary classification, ranked threat categories, MITRE ATT&CK techniques and CWE references, with a full audit trail. |
| **AI analyst** | Claude writes an executive summary, key findings and recommended actions when `ANTHROPIC_API_KEY` is set; otherwise a deterministic template does. |
| **Reports** | PDF and Markdown (indicators defanged), STIX 2.1 bundles (observables, indicators, attack-patterns, relationships, report) and raw JSON. |
| **History** | Every investigation is stored (SQLite by default, PostgreSQL supported) with search, severity filters and dashboard statistics. |
| **Security** | Optional API-key authentication, per-client rate limiting, security headers, upload size limits and zip-bomb guards. |
| **Dashboard** | React analyst UI: investigate text or files, inspect findings, ATT&CK mapping, email/file analysis and indicators, export reports, browse history, view system status. |

---

## Investigation pipeline

```
Input ─► Ingestion ─► Evidence collection ─► Normalization ─► Validation ─► Threat intel ─► Risk engine ─► AI analyst
(text,   (parsers:     (IOC extractor +       (refang,          (RFC/TLD/     (7 providers,   (27 rules,     (explains;
 files)   eml, pdf,     seeded file hashes)    canonicalize)     scope checks)  concurrent)     ATT&CK, CWE)   never scores)
          qr, apk)
                                                                                                 │
                                                       History (SQL) ◄── Reports (PDF · Markdown · STIX 2.1 · JSON)
```

Each stage runs inside an isolation boundary: a failing stage is recorded (with secrets sanitized) and the
investigation continues as `partial_success`.

---

## Quick start

### Docker (full stack)

```bash
cp backend/.env.example backend/.env   # add any provider keys you have
docker compose up --build
```

- Dashboard: <http://localhost:8080>
- API docs (Swagger): <http://localhost:8000/docs>

Compose runs PostgreSQL, the API (with Tesseract for OCR) and the nginx-served dashboard.

### Local development

**Backend** (Python 3.10+):

```bash
cd backend
python -m venv venv && source venv/bin/activate      # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload --port 8000
```

**Frontend** (Node.js 18+), in a second terminal:

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000 (override with VITE_API_PROXY)
```

For a production frontend build pointed at a remote API, set `VITE_API_BASE_URL` and run `npm run build`.

OCR needs the `tesseract-ocr` system package (installed in the Docker image). Without it, images are still decoded for QR
codes and fingerprinted.

### Tests

```bash
cd backend && python -m pytest -q      # 117 tests, fully offline (HTTP providers and Claude are mocked)
cd frontend && npm run build           # type-check + production build
```

CI (`.github/workflows/ci.yml`) runs both, then builds the Docker images.

---

## Configuration

All settings are environment variables (or `backend/.env`). See `backend/.env.example`.

| Variable | Default | Purpose |
|---|---|---|
| `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `URLHAUS_AUTH_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `HIBP_API_KEY` | empty | Each provider is enabled when its key is set. |
| `INTEL_KEYLESS_PROVIDERS` | `true` | Enable Shodan InternetDB and RDAP (outbound calls, no key). |
| `INTEL_TIMEOUT_SECONDS` / `INTEL_CONCURRENCY` / `INTEL_MAX_ARTIFACTS_PER_CATEGORY` | `8` / `8` / `25` | Lookup tuning. |
| `ANTHROPIC_API_KEY` | empty | Enables the Claude-written analyst report. |
| `ANALYST_ENABLED` / `ANALYST_MODEL` / `ANALYST_EFFORT` | `true` / `claude-opus-5-5` / `medium` | Analyst behaviour. |
| `DATABASE_URL` | `sqlite:///./reconiq.db` | e.g. `postgresql+psycopg://user:pass@host/db`. |
| `PERSIST_INVESTIGATIONS` | `true` | Save investigations to history. |
| `API_KEYS` | empty | Comma-separated keys; when set, every endpoint except health requires `X-API-Key` or `Authorization: Bearer`. |
| `RATE_LIMIT_PER_MINUTE` | `60` | Per-client limit on API routes (`0` disables). In-process; use a shared store with multiple replicas. |
| `MAX_UPLOAD_MB` | `15` | Upload size cap. |
| `CORS_ORIGINS` | localhost dev ports | Allowed browser origins. |

---

## API

| Method & path | Description |
|---|---|
| `GET /api/v1/health` | Liveness and version (always public). |
| `POST /api/v1/evidence/investigate` | Investigate text: `{"text": "...", "refang": true}`. |
| `POST /api/v1/evidence/investigate/file` | Investigate an upload (multipart `file`, optional `refang`). |
| `POST /api/v1/evidence/extract` | Extract indicators only, no scoring. |
| `GET /api/v1/investigations` | History: `limit`, `offset`, `severity`, `q` (search). |
| `GET /api/v1/investigations/stats` | Totals, last 7 days, average score, severity and classification breakdowns. |
| `GET /api/v1/investigations/{id}` | Full stored result. |
| `DELETE /api/v1/investigations/{id}` | Delete an investigation. |
| `GET /api/v1/investigations/{id}/report?format=pdf\|markdown\|stix\|json` | Export a report. |
| `GET /api/v1/system/capabilities` | Providers, analyst mode, ingestion features, limits and the rule catalogue. |

Example:

```bash
curl -s localhost:8000/api/v1/evidence/investigate \
  -H 'Content-Type: application/json' \
  -d '{"text": "URGENT: verify your password at hxxps://paypal-account-security[.]xyz/signin"}' | jq .risk_assessment.classification
# "credential_harvesting"

curl -s -F file=@suspicious.eml localhost:8000/api/v1/evidence/investigate/file | jq .risk_assessment.total_score
```

The response includes evidence, normalized evidence, validation results, intel responses, the risk assessment (findings
with ATT&CK/CWE context, applied rules, classification), the analyst report, ingestion analysis and per-stage timings.

---

## Detection rules

Scores are the capped sum of matched rule weights. Severity bands: 0–19 Informational, 20–39 Low, 40–59 Medium, 60–79 High, 80–100 Critical.

| Rule | Name | Severity | Weight |
|---|---|---|---|
| RULE_VAL_001 | Invalid URL Detected | MEDIUM | 25 |
| RULE_VAL_002 | Invalid Domain or IP Masquerade | HIGH | 50 |
| RULE_VAL_003 | Invalid Email Structure | LOW | 10 |
| RULE_INT_001 | Threat Intel Provider Flagged Malicious | HIGH | 50 |
| RULE_INT_002 | Multi-Provider Threat Consensus | CRITICAL | 80 |
| RULE_INT_003 | Threat Intel Provider Failure | INFORMATIONAL | 0 |
| RULE_INT_004 | Newly Registered Domain (< 30 days) | HIGH | 50 |
| RULE_EVI_001 | Defanged Indicator Obfuscation Detected | MEDIUM | 25 |
| RULE_EVI_002 | High Artifact Density (≥ 8) | MEDIUM | 25 |
| RULE_EVI_003 | Public IP Address Present | LOW | 10 |
| RULE_EVI_004 | Brand Impersonation Domain | HIGH | 50 |
| RULE_EVI_005 | Deceptive Keyword Domain | MEDIUM | 25 |
| RULE_EVI_006 | Punycode / Homograph Domain | MEDIUM | 25 |
| RULE_EVI_007 | High-Abuse Top-Level Domain | LOW | 10 |
| RULE_EVI_008 | URL Shortener Concealment | LOW | 10 |
| RULE_EVI_009 | IP-Literal URL | MEDIUM | 25 |
| RULE_EVI_010 | Non-Standard Port | LOW | 10 |
| RULE_EVI_011 | Executable Payload Download | HIGH | 50 |
| RULE_CNT_001 | Credential Phishing Language | MEDIUM | 25 |
| RULE_CNT_002 | Financial or Tech-Support Scam Language | MEDIUM | 25 |
| RULE_EML_001 | Email Authentication Failure | HIGH | 50 |
| RULE_EML_002 | Reply-To / Return-Path Mismatch | MEDIUM | 25 |
| RULE_EML_003 | Display Name Spoofing | MEDIUM | 25 |
| RULE_FIL_001 | Dangerous File or Attachment | HIGH | 50 |
| RULE_FIL_002 | QR Code Leading to URL | MEDIUM | 25 |
| RULE_FIL_003 | Android App With Dangerous Permissions | HIGH | 50 |
| RULE_FIL_004 | PDF Active Content | HIGH | 50 |

A provider result counts as a malicious verdict only when the lookup succeeded **and** returned a MEDIUM-or-higher
threat indicator; provider confidence alone never flags an artifact.

---

## Repository layout

```
backend/
  app/
    api/v1/endpoints/   evidence, investigations (history + reports), system, health
    analyst/            Claude narrative + deterministic template
    core/               settings, logging, security (auth, rate limiting, headers)
    db/                 SQLAlchemy models, session, repository
    ingestion/          IOC extractor, collector, parsers (email, pdf, image, apk, file_info)
    integrations/       provider base, HTTP base, manager, registry, providers/*
    knowledge/          MITRE ATT&CK, CWE, threat taxonomy, severity
    pipeline/           orchestrator, context, steps
    reports/            STIX 2.1, Markdown, PDF
    risk_engine/        rules, extended content rules, scorer, confidence, weights
    utils/, validators/ normalizer, regex patterns, validator
  tests/                117 offline tests
frontend/
  src/pages/            Investigate, History, Investigation, System
  src/components/       result panels, input, export menu, …
docker-compose.yml      Postgres + API + dashboard
.github/workflows/      CI
```

---

## Known limitations

- Outlook `.msg` files aren't parsed; save them as `.eml`.
- Rate limiting and provider caches are in-process; multi-replica deployments should move them to a shared store.
- No user accounts or multi-tenancy: access control is shared API keys.
