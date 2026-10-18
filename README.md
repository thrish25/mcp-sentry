# MCP-Sentry: Runtime Security Gateway for AI Agents

[![IBM Z Datathon 2026](https://img.shields.io/badge/IBM%20Z-Datathon%202026-052FAD.svg)](https://www.ibm.com)
[![Backend](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![Frontend](https://img.shields.io/badge/Next.js-16.4+-black.svg)](https://nextjs.org)
[![Testing](https://img.shields.io/badge/pytest-82%20passed-success.svg)](https://docs.pytest.org)
[![Security](https://img.shields.io/badge/Zero--Trust-Default--Deny-critical.svg)](https://csrc.nist.gov)

**MCP-Sentry** is a deterministic, enterprise-grade **Runtime Security Gateway** engineered to arbitrate, govern, and audit Model Context Protocol (MCP) tool invocations executed by autonomous AI agents. Built as a zero-trust defense perimeter for enterprise IBM Z environments, MCP-Sentry prevents prompt injections, unauthorized shadow tools, path traversal escapes, and credential exfiltration before any mock action executes.

---

## 🏗️ Repository Architecture

This repository is organized as a clean, self-contained monorepo:

```text
mcp-sentry/
├── backend/
│   ├── app/
│   │   ├── __init__.py          # Backend package init
│   │   ├── agent.py             # Simulated AI agent with preset & custom scenarios
│   │   ├── canary.py            # Synthetic canary tokens & exfiltration detection
│   │   ├── config.py            # Application configuration & environment settings
│   │   ├── database.py          # SQLite WAL-mode audit & mock data persistence
│   │   ├── evaluation.py        # Demo scenarios (7/7) & evaluation benchmark engine (22 cases)
│   │   ├── execution.py         # Execution service with mandatory policy recheck
│   │   ├── main.py              # FastAPI entrypoint with restricted CORS & routes
│   │   ├── policy.py            # Deterministic policy engine & permission catalog
│   │   ├── sandbox.py           # Isolated mock tool sandbox (files, outbox, network)
│   │   └── schemas.py           # Pydantic v2 validation contracts & demo schemas
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── test_audit_canary.py # Audit logging & canary detection tests (19 tests)
│   │   ├── test_evaluation.py   # Predefined demo & empirical evaluation tests (4 tests)
│   │   ├── test_health.py       # Health & baseline endpoint tests (2 tests)
│   │   ├── test_integration.py  # Full-stack integration & CORS tests (9 tests)
│   │   ├── test_policy.py       # Deterministic policy engine & traversal tests (28 tests)
│   │   └── test_sandbox.py      # Sandbox isolation & approval cycle tests (20 tests)
│   ├── requirements.txt         # Backend Python dependencies
│   └── .env.example             # Backend environment template
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── globals.css      # Dark cybersecurity operations theme
│   │   │   ├── layout.tsx       # Next.js root layout with metadata
│   │   │   └── page.tsx         # Security console orchestrator & live data polling
│   │   ├── components/
│   │   │   ├── CanaryFindings.tsx   # Honeypot registry & forensic incident ledger
│   │   │   ├── DemoControlPanel.tsx # 1-Click 7-step demo, benchmark modal & manual triggers
│   │   │   ├── EventTimeline.tsx    # Filterable audit feed with inline approvals
│   │   │   ├── EvidencePanel.tsx    # Forensic rationale & correlated findings
│   │   │   ├── Header.tsx           # Gateway health indicator & sync controls
│   │   │   ├── OverviewCards.tsx    # SOC metrics & high-impact KPI cards
│   │   │   ├── SandboxView.tsx      # Mock files, local outbox, and network logs
│   │   │   └── ToolCallInspector.tsx # Deep-dive argument viewer & IDs
│   │   └── lib/
│   │       ├── api.ts           # Typed API client with human-readable error parser
│   │       └── types.ts         # TypeScript interfaces mirroring FastAPI schemas
│   ├── package.json             # Next.js 16.4+, React 19, Tailwind CSS v4 dependencies
│   ├── tsconfig.json            # TypeScript strict configuration
│   └── .env.example             # Frontend API URL configuration
├── docs/
│   ├── architecture.md          # Architecture & security design
│   ├── evaluation_report.md     # Phase 7 evaluation & empirical benchmark report
│   ├── FINAL_CHECKLIST.md       # Phase 8 final verification checklist & results
│   └── setup_windows.md         # Detailed Windows PowerShell runbook
├── .gitignore                   # Multi-language ignore rules
├── PROJECT_STATUS.md            # Active phase tracker & verification records
└── README.md                    # Project documentation
```

---

## ⚙️ Tech Stack & Constraints

- **Backend**: Python 3.10+, [FastAPI](https://fastapi.tiangolo.com/), [Pydantic v2](https://docs.pydantic.dev/), [Uvicorn](https://www.uvicorn.org/)
- **Frontend**: [Next.js](https://nextjs.org/) 16.4+ (App Router, Turbopack), [React](https://react.dev/) 19, [TypeScript](https://www.typescriptlang.org/), [Tailwind CSS](https://tailwindcss.com/) v4
- **Database**: [SQLite](https://sqlite.org/) (WAL mode, busy timeout, zero-latency local audit ledger)
- **Testing**: [pytest](https://docs.pytest.org/) (82 automated tests passing) & ESLint / Next.js type check
- **Constraints**: **100% Mock Data & Isolated Execution**. No external LLM APIs, no paid cloud services, no real sockets, no real file alterations outside synthetic stores.

---

## 🚀 Quick Start (Windows PowerShell)

### 1. Prerequisites Check

Open Windows PowerShell and verify installed runtimes:

```powershell
python --version   # Python 3.10 or higher
node -v            # Node.js 18 or higher
npm -v             # npm 9 or higher
```

### 2. Backend Setup & Run

From the project root directory:

```powershell
# 1. Install backend dependencies (if not already installed)
python -m pip install -r backend/requirements.txt

# 2. Run backend test suite (82 tests across 6 suites)
python -m pytest backend/tests -v

# 3. Launch the FastAPI Gateway on port 8000
python -m uvicorn app.main:app --app-dir backend --reload --host 127.0.0.1 --port 8000
```

- **Gateway Health**: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

### 3. Frontend Setup & Run

In a second Windows PowerShell terminal:

```powershell
# 1. Navigate to frontend
Set-Location -Path "frontend"

# 2. Install dependencies (if needed)
npm install

# 3. Run production build check or dev server
npm run build
npm run dev
```

- **Web Security Operations Dashboard**: [http://localhost:3000](http://localhost:3000)

---

## 🛡️ Security Architecture & Invariants

```text
[ Autonomous AI Agent ]
         │
         ▼  (Inbound MCP Tool Invocation)
┌────────────────────────────────────────────────────────┐
│                   MCP-SENTRY GATEWAY                   │
│  1. Inbound Request Sanitization & Schema Validation   │
│  2. Deterministic Policy Arbitration (ALLOW/BLOCK/APP) │
│  3. Synthetic Canary Detection (Investigative Signal)  │
│  4. Persistent SQLite WAL Audit Ledger                 │
└────────────────────────────────────────────────────────┘
         │
    ┌────┴───────────────────────────┬──────────────────────────┐
    ▼                                ▼                          ▼
[ ALLOW ]                   [ REQUIRE_APPROVAL ]            [ BLOCK ]
Executed strictly on         Suspended; held pending        Default-deny halts
isolated mock data store     human authorization action     unauthorized action
```

### Core Security Invariants:
1. **Default-Deny Stance**: Any unlisted tool, invalid argument, or unauthorized destination is immediately blocked with a deterministic policy rule ID.
2. **Untrusted Caller Metadata**: Origin and destination parameters are treated as untrusted input; the caller cannot grant itself permissions.
3. **Approval Policy Recheck**: Resolving an approval re-runs `PolicyEngine.evaluate()`. If a blocked action is approved, execution is rejected (`ValueError`), enforcing defense-in-depth.
4. **Decoupled Canary Detection**: Synthetic canaries (`CANARY-IBMZ-SEC-KEY-9941`) provide forensic tripwires. Accessing a canary emits an investigative finding without altering policy permissions.
5. **CORS Boundary**: Gateway strictly restricts cross-origin access to local frontend development origins (`http://localhost:3000` and `http://127.0.0.1:3000`).

---

## 🧪 Demonstration & Evaluation Suite

### Option A: One-Click Web Dashboard Demonstration

1. Open [http://localhost:3000](http://localhost:3000).
2. Click **"RUN 7-STEP DEMO (1-CLICK)"** at the top of the *Agent Demonstration & Evaluation Suite* panel.
3. Observe real-time sequential arbitration of all 7 predefined scenarios:
   - Step 1: Legitimate Read of Allowed File → `ALLOW` (`POL-ALLOW-READ-SANDBOX`)
   - Step 2: Attempt to Read Restricted File (`../../etc/shadow`) → `BLOCK` (`POL-BLOCK-PATH-TRAVERSAL`)
   - Step 3: Attempt to Use Unknown Tool (`execute_raw_binary`) → `BLOCK` (`POL-DEFAULT-DENY-UNKNOWN-TOOL`)
   - Step 4: Disallowed Network Destination (`external-cloud-exfil`) → `BLOCK` (`POL-BLOCK-DISALLOWED-DEST`)
   - Step 5: Action Requiring Human Approval (`send_email`) → `REQUIRE_APPROVAL` (auto-approved to `APPROVED_EXECUTED`)
   - Step 6: Access to Synthetic Canary Value → `ALLOW` + Canary Finding Emitted
   - Step 7: Paraphrased Dangerous Shell Command (`rm -rf /`) → `BLOCK` (`POL-BLOCK-DANGEROUS-COMMAND`)
4. Click **"EVALUATION REPORT (22 CASES)"** to inspect empirical security metrics and the complete test case breakdown.

### Option B: PowerShell REST API Commands

```powershell
# 1. Execute the 7-Step Sequential Demonstration:
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/evaluation/demo" | ConvertTo-Json -Depth 4

# 2. Run the 22-Case Empirical Benchmark Suite:
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/evaluation/run" | ConvertTo-Json -Depth 5
```

---

## 📊 Measured Evaluation Results

Evaluated over the **22 labeled test cases** in `backend/app/evaluation.py` against the real SQLite audit ledger:

| Evaluation Metric | Measured Result | Numerator / Denominator | Outcome |
| :--- | :---: | :---: | :---: |
| **Unauthorized-Call Block Rate** | **100.0%** | **10 / 10** threats blocked | **PASSED** |
| **Legitimate-Action False-Block Rate** | **0.0%** | **0 / 12** false blocks | **PASSED** |
| **Canary Detection Precision** | **100.0%** | **4 / (4 + 0)** alerts | **PASSED** |
| **Canary Detection Recall** | **100.0%** | **4 / (4 + 0)** captured | **PASSED** |
| **Audit-Record Completeness** | **100.0%** | **22 / 22** ledger entries | **PASSED** |

*See [`docs/evaluation_report.md`](docs/evaluation_report.md) for full methodology and [`docs/FINAL_CHECKLIST.md`](docs/FINAL_CHECKLIST.md) for the final verification checklist.*

---

## 🗺️ Project Status Log

See [`PROJECT_STATUS.md`](PROJECT_STATUS.md) for the comprehensive development and verification record spanning Phases 1 through 8.
