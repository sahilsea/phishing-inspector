# Phishing Inspector — Real-Time Heuristic Scam Threat Engine & Telemetry Dashboard

[![TypeScript 5.5+](https://img.shields.io/badge/TypeScript-5.5+-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React 18](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vitest](https://img.shields.io/badge/Tested%20with-Vitest-6E9F18?logo=vitest&logoColor=white)](https://vitest.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4-38B2AC?logo=tailwind-css&logoColor=white)](https://tailwindcss.com/)
[![Engine Version](https://img.shields.io/badge/Heuristic_Engine-v2.4-cyan)](#)

---

## 1. Executive Summary & Threat Landscape

Modern employment phishing and rental scam syndicates employ sophisticated social engineering tactics designed to deceive job seekers and corporate candidates. Typical vectors include:
1. **Advance-Fee Equipment Frauds:** Issuing forged counterfeit electronic checks (\$4,000–\$5,000) and demanding immediate wire, Zelle, or CashApp payments to fake "certified hardware vendors" before the check bounces.
2. **Domain Spoofing & Lookalike Typosquatting:** Impersonating reputable enterprises (e.g. `apple-careers-portal.com`, `meta-recruiting-desk.net`) or conducting recruitment exclusively via free webmail (`@gmail.com`, `@yahoo.com`).
3. **Off-Grid Coercive Dark Patterns:** Directing candidate communications through consumer chat platforms (Telegram, WhatsApp), enforcing artificial 24–48 hour ultimatums, and demanding high-value PII (passport scans, government ID) prior to interviews.

**Phishing Inspector** provides a zero-retention, offline-capable forensic analyzer that evaluates document payloads and job listing URLs in sub-second latency, computing a deterministic **Scam Threat Index (0–100%)** backed by verifiable heuristic evidence.

---

## 2. Architecture & Telemetry Pipeline

The engine executes in an isolated sandbox with zero external data exfiltration. The end-to-end data flow is depicted below:

```text
+---------------------------------------------------------------------------------------+
|                                 INPUT PAYLOAD VECTOR                                  |
|                 (Raw Offer Text Payload OR Job Listing Target URL)                     |
+-------------------------------------------+-------------------------------------------+
                                            |
                                            v
+---------------------------------------------------------------------------------------+
|                            PARSER & ENTITY EXTRACTION LAYER                           |
|       - Extract URLs, Domain Hostnames, Sender/Reply-To Emails, and Text Tokens       |
+-------------------+-----------------------+-----------------------+-------------------+
                    |                       |                       |
                    v                       v                       v
+-----------------------+ +-----------------------+ +-----------------------------------+
| PAYMENT DETECTOR      | | DOMAIN INSPECTOR      | | DARK PATTERN SCANNER              |
| Weight: 45%           | | Weight: 30%           | | Weight: 25%                       |
|-----------------------| |-----------------------| |-----------------------------------|
| - Counterfeit Checks  | | - Major Brand Clones  | | - <48h Artificial Urgency         |
| - Wire / Zelle / Venmo| | - Free Webmail Hiring | | - Telegram / WhatsApp Screening   |
| - Bogus Vendors       | | - Suspicious TLDs     | | - Premature PII / Passport Demand |
| - Crypto Wallets      | | - Privacy Proxy Age   | | - Instant Hire / Skipped Interview|
+-----------+-----------+ +-----------+-----------+ +-----------------+-----------------+
            |                         |                               |
            +-------------------------+-------------------------------+
                                      |
                                      v
+---------------------------------------------------------------------------------------+
|                               COMPOSITE THREAT ENGINE                                 |
|   Threat Index = min(100, (FinancialRisk * 0.45) + (DomainRisk * 0.30) + (Dark * 0.25))|
+-------------------------------------+-------------------------------------------------+
                                      |
       +------------------------------+------------------------------+
       |                              |                              |
       v                              v                              v
 [ 0% - 30% ]                  [ 31% - 69% ]                  [ 70% - 100% ]
 Clean Offer (Safe)      Suspicious (Gray Zone)          Critical Danger
 Standard Enterprise      Moderate Anomalies             Immediate Cease & Desist
```

---

## 3. Heuristic Scoring Matrix & Formula Calibration

### 3.1 Composite Formula
$$\text{Threat Index} = \min\left(100, \left(\text{FinancialRisk} \times 0.45\right) + \left(\text{DomainRisk} \times 0.30\right) + \left(\text{DarkPatternRisk} \times 0.25\right)\right)$$

### 3.2 Verdict Thresholds
| Range | Category | Action Mandate Level | Recommended Action Directive |
| :--- | :--- | :---: | :--- |
| **0% – 30%** | `Clean Offer` | `SAFE` | Standard enterprise workflow verified; proceed via corporate platform. |
| **31% – 69%** | `Suspicious (Gray Zone)` | `CRITICAL` | Exercise caution; withhold identity assets; verify via corporate switchboard. |
| **70% – 100%** | `Critical Danger` | `CRITICAL` | Immediate cease & desist; advance-fee fraud detected; do not deposit or wire funds. |

### 3.3 Engine Heuristic Breakdown
| Engine Module | Detection Rules & Signatures | Default Severity | Risk Weight |
| :--- | :--- | :---: | :---: |
| **Financial Trap** | Electronic / cashier checks with deposit mandates | `CRITICAL` | 40% |
| | Non-reversible transfers (Zelle, CashApp, Wire, MoneyGram) | `CRITICAL` | 45% |
| | Redirection to "approved hardware / equipment vendors" | `CRITICAL` | 35% |
| | Cryptocurrency wallet addresses (Bitcoin, Ethereum, USDT) | `CRITICAL` | 50% |
| | Upfront onboarding, training, or screening fees | `CRITICAL` | 35% |
| **Domain Trust** | Corporate brand lookalike/typosquatting (`apple-careers-portal.com`) | `CRITICAL` | 50% |
| | Corporate hiring from commercial webmail (`@gmail.com`, `@yahoo.com`) | `CRITICAL` | 45% |
| | High-abuse disposable TLDs (`.work`, `.top`, `.xyz`, `.biz`, `.click`) | `WARNING` | 25% |
| | Domain age < 30 days registered behind privacy proxy | `CRITICAL` | 40% |
| **Dark Patterns** | Artificial deadlines under 48 hours ("within 24 hours", "midnight") | `WARNING` | 30% |
| | Screening conducted on consumer messaging (Telegram, WhatsApp) | `WARNING` | 35% |
| | Premature PII extraction (color scan of government photo ID / passport) | `WARNING` | 45% |
| | Direct hire without substantive technical evaluation | `CRITICAL` | 40% |

---

## 4. Codebase Structure

```text
.
├── UI/
│   ├── PhishingDashboard.tsx        # React UI component with active state, tab toggling & handlers
│   ├── code.html                    # Original cybersecurity visual presentation reference
│   └── screen.png                   # Design layout reference screenshot
├── src/
│   ├── engine/
│   │   ├── darkPatternScanner.ts    # Coercion, urgency, and interview anomaly heuristics
│   │   ├── domainInspector.ts       # Domain age simulation, lookalike, and email analysis
│   │   ├── paymentDetector.ts       # Advance-fee, wire transfer, and crypto extraction
│   │   ├── sampleData.ts            # Realistic demo test payloads (Scam, Gray Zone, Clean)
│   │   └── threatCalculator.ts      # Weighted composite formula & action mandate generator
│   ├── tests/
│   │   └── inspector.test.ts        # Vitest automated test suite covering all threat levels
│   ├── types/
│   │   └── inspector.ts             # Strict TypeScript contracts and telemetry schemas
│   ├── index.css                    # Tailwind base, radar animations, and cyber styles
│   └── main.tsx                     # React application mount entrypoint
├── index.html                       # HTML5 entrypoint with Google Fonts
├── package.json                     # Dependency manifest and execution scripts
├── tsconfig.json                    # Strict TypeScript 5+ compiler configuration
├── vite.config.ts                   # Vite bundler and Vitest test runner configuration
└── README.md                        # Executive technical specification
```

---

## 5. Local Setup & Verification Guide

### Prerequisites
- Node.js 18+ (tested on Node v20/v26)
- npm 9+ or pnpm / yarn

### Installation
```bash
npm install
# or if resolving with peer dependencies:
npm install --legacy-peer-deps
```

### Running Automated Test Suite
The automated test suite evaluates realistic payloads, individual heuristic engines, and composite score boundary conditions:
```bash
npm run test
```

### Type Checking & Linting
Verify 100% strict TypeScript compliance:
```bash
npm run lint
```

### Running Development UI Server
Start the local Vite development server:
```bash
npm run dev
```
Navigate to `http://localhost:5173` to interact with the dashboard:
- **Toggle Mode:** Switch between `Text / Payload` and `Job Listing URL`.
- **Quick Presets:** Click `Blatant Scam`, `Gray Zone`, or `Clean Offer` to trigger live telemetry.
- **Forensic Scan:** Click `Forensic Scan` to view the 350ms loading radar and animated results.
- **Deep Gemini AI:** Click `Deep Gemini AI` to trigger real-time neural LLM threat intelligence via Google Gemini 3.5 Flash-Lite.
- **Audit Tools:** Use `Copy Threat Hash` for SHA-256 telemetry hashing, `Export PDF Report` for print-ready audit logs, and `Isolate Domain` to trigger DNS sinkhole isolation.

### Running Gemini AI Neural Evaluator CLI
Evaluate all three presets using the configured Google Gemini API key:
```bash
npm run evaluate:gemini
```

