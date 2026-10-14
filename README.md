# ReconIQ

### Enterprise Cybersecurity Investigation Platform

**Evidence. Intelligence. Trust.**

> **Tagline**: *Evidence. Intelligence. Trust.*

**ReconIQ** is an enterprise-grade cybersecurity threat analysis platform built with FastAPI, Python, and a modular architecture. ReconIQ operates on a **deterministic-first investigation pipeline** where evidence collection, normalization, threat intelligence enrichment, and rule-based risk engines strictly govern security assessments before AI report generation.

---

## 🛡️ Core Architectural Principle

> **AI is NEVER responsible for deciding whether an artifact or input is malicious.**

Threat detection, risk scoring, and evidence validation are strictly driven by deterministic rule engines, MITRE ATT&CK taxonomies, and verified intelligence integrations. The AI Analyst functions exclusively to explain aggregated evidence and compile human-readable investigation summaries.

---

## ⚙️ Investigation Pipeline Architecture

```
User Input ──► Ingestion ──► Evidence Collector ──► Normalization ──► Validators
                                                                          │
                                                                          ▼
Report Generator ◄── AI Analyst ◄── Risk Engine ◄── Threat Intel ◄── Pipeline
```

### Pipeline Stage Breakdown

1. **User Input**: Ingests raw text, email content, file uploads, URLs, or browser data.
2. **Ingestion (`app/ingestion/`)**: Multi-source entry layer handling artifact ingestion (text, QR, OCR, PDF, APK, headers).
3. **Evidence Collector (`app/ingestion/extractors/`)**: Extracts granular technical indicators (IOC Extractor for IPv4, IPv6, URLs, Domains, Email addresses, Phone numbers).
4. **Normalization (`app/utils/normalizer.py`)**: Standardizes extracted elements (refanging `hxxp` ➔ `http`, `[.]` ➔ `.`, `[at]` ➔ `@`).
5. **Validators**: Performs RFC IP checks, TLD verification, syntax validation, and private address filtering.
6. **Pipeline (`app/pipeline/`)**: Central orchestrator managing investigation state transitions and context accumulation.
7. **Threat Intelligence Integrations (`app/integrations/`)**: Asynchronous lookup clients for external threat intel providers (VirusTotal, AbuseIPDB, Shodan, WHOIS, PhishTank, HIBP, etc.).
8. **Risk Engine (`app/risk_engine/`)**: Deterministic decision-making engine calculating evidence-based risk scores (0-100), rule matches, and confidence metrics.
9. **AI Analyst**: Summarizes findings and provides natural language context exclusively based on accumulated evidence.
10. **Report Generator**: Produces final structured JSON, STIX 2.1 threat objects, or executive PDF reports.

---

## 📁 Repository Folder Structure

```
backend/
├── app/
│   ├── __init__.py                     # Package metadata
│   ├── main.py                         # FastAPI application entrypoint
│   ├── api/                            # API endpoints & presentation layer
│   │   └── v1/
│   │       ├── router.py              # Central API v1 router
│   │       └── endpoints/
│   │           ├── evidence.py        # Evidence extraction API (/api/v1/evidence/extract)
│   │           └── health.py          # System telemetry & health check (/api/v1/health)
│   ├── core/                           # Configuration & logging infrastructure
│   │   ├── config.py                  # Pydantic BaseSettings management
│   │   └── logging.py                 # Structured security audit logging
│   ├── ingestion/                      # Multi-source ingestion & evidence extraction
│   │   ├── ingested_input.py          # IngestedInput data model
│   │   ├── collector.py               # EvidenceCollector primary facade
│   │   └── extractors/
│   │       ├── base.py                # Abstract Base Extractor interface
│   │       └── ioc_extractor.py       # Production IOC Extractor component
│   ├── pipeline/                       # Workflow & Investigation state manager [Placeholder]
│   │   ├── investigation.py           # Investigation pipeline controller
│   │   ├── context.py                 # InvestigationContext state holder
│   │   └── steps.py                   # Modular pipeline step definitions
│   ├── risk_engine/                    # Deterministic risk scoring engine [Placeholder]
│   │   ├── scorer.py                  # Risk scoring calculator facade
│   │   ├── rules.py                   # Threat detection rule declarations
│   │   ├── weights.py                 # Severity weight definitions
│   │   └── confidence.py              # Evidence-based confidence calculator
│   ├── knowledge/                      # Cybersecurity taxonomies & frameworks [Placeholder]
│   │   ├── severity.py                # Platform severity enums
│   │   ├── taxonomy.py                # Threat classification taxonomy
│   │   ├── mitre_attack.py            # MITRE ATT&CK matrix mappings
│   │   └── cwe.py                     # CWE weakness mappings
│   ├── integrations/                   # Threat intelligence integrations [Placeholder]
│   │   └── base.py                    # Base async Threat Intel provider interface
│   ├── services/                       # Application services layer
│   │   └── investigation_service.py     # Investigation orchestrator
│   ├── schemas/                        # Pydantic v2 DTOs
│   │   ├── evidence.py                # Evidence request & response schemas
│   │   ├── ioc.py                     # Categorized IOC data schemas
│   │   └── health.py                  # Health check schema
│   └── utils/                          # Utilities & normalizers
│       ├── normalizer.py              # Defang refanging & string normalizers
│       └── regex_patterns.py          # RFC-compliant regular expressions
├── tests/                              # Pytest suite
│   ├── conftest.py
│   └── test_ioc_extractor.py          # IOC extraction & defang unit tests
├── .env.example                        # Environment template
├── pyproject.toml                      # Package config
├── requirements.txt                    # Production & dev dependencies
└── README.md                           # Platform documentation
```

---

## 🚀 Running the Application

### 1. Prerequisites
- Python 3.10+
- `pip` or virtual environment manager

### 2. Installation
```bash
cd backend
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 3. Start Development Server
```bash
uvicorn app.main:app --reload --port 8000
```
- Interactive Swagger API Docs: `http://localhost:8000/docs`
- ReDoc API Documentation: `http://localhost:8000/redoc`

### 4. Run Automated Tests
```bash
pytest
```

### 5. Start the Analyst Dashboard (frontend)
Requires Node.js 18+. With the backend running on port 8000:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173`. The Vite dev server proxies `/api` to `http://localhost:8000`
(override with `VITE_API_PROXY`). For a deployed build, set `VITE_API_BASE_URL` and run `npm run build`.

The dashboard lets you paste or load sample evidence and shows the risk score and severity,
per-stage pipeline timing, findings, the full rule audit trail, every extracted indicator with
its validation properties and threat-intel status, plus JSON export and local investigation history.

---

## 🔍 API Usage Example

### Extract Indicators of Compromise (IOCs)
**Endpoint**: `POST /api/v1/evidence/extract`

**Request Body**:
```json
{
  "text": "Alert: Phishing email from support[at]secure-bank[dot]com containing link hxxps://malicious-domain[.]com/login and IP 192.168.1.1 or 2001:db8::1. Call +1-800-555-0199."
}
```

**Response Body**:
```json
{
  "status": "success",
  "execution_time_ms": 2.45,
  "summary": {
    "total_iocs": 5,
    "ipv4_count": 1,
    "ipv6_count": 1,
    "url_count": 1,
    "domain_count": 1,
    "email_count": 1,
    "phone_count": 1
  },
  "results": {
    "ipv4": ["192.168.1.1"],
    "ipv6": ["2001:db8::1"],
    "urls": ["https://malicious-domain.com/login"],
    "domains": ["secure-bank.com", "malicious-domain.com"],
    "emails": ["support@secure-bank.com"],
    "phone_numbers": ["+18005550199"]
  }
}
```

---

## 📌 Roadmap & Status

**Done**
- [x] IOC extraction (IPv4/IPv6, URLs, domains, emails, phone numbers) with defang/refang normalization
- [x] Structural validators (RFC IP checks, TLD verification, private/reserved classification)
- [x] Pipeline orchestrator with per-stage isolation, telemetry and secret sanitization
- [x] Threat-intel framework (provider base class, manager, caching, rate limiting) + VirusTotal provider
- [x] Deterministic risk engine: 9 rules, weighted scoring, severity mapping, confidence engine
- [x] REST API: `/health`, `/evidence/extract`, `/evidence/investigate`
- [x] React analyst dashboard (`frontend/`)

**Pending**
- [ ] **Ingestion Layer**: OCR, QR Code decoding, raw email `.eml`/`.msg` header parser, PDF & file metadata extractors (source types are declared but only raw text is handled; no file-upload endpoint yet).
- [ ] **More Threat Intel Providers**: AbuseIPDB, Shodan, WHOIS, Google Safe Browsing, PhishTank, HIBP (config keys exist, no clients).
- [ ] **Knowledge Base**: MITRE ATT&CK / CWE / taxonomy modules are small placeholder dictionaries and are not yet linked to rules or findings.
- [ ] **AI Analyst**: Contextual LLM summary generation based strictly on verified evidence.
- [ ] **Report Generator**: STIX 2.1 bundles and executive PDF reports.
- [ ] **Database & Multi-tenancy**: PostgreSQL/SQLModel persistence for investigation history (the dashboard currently keeps history in the browser only).
- [ ] **Auth & hardening**: API authentication, request rate limiting, Docker/CI setup.
