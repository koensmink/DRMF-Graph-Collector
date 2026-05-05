# DRMF Graph Collector

Deterministic Microsoft Graph–based collector for measuring security controls in the **Digital Resilience Maturity Framework (DRMF)**.

This project extracts objective security configuration evidence from Microsoft Entra ID, Intune, Identity Governance and related Microsoft Graph sources. The collector can optionally enrich results with AI for contextual interpretation and remediation guidance.

The core design principle is:

```text
Truth = Graph + deterministic rules
Interpretation = optional AI enrichment
```

AI is never used for scoring or pass/fail decisions.

---

## Purpose

Microsoft security posture is fragmented across multiple portals, APIs and policy surfaces.

This collector helps by providing:

- Centralized evidence extraction via Microsoft Graph
- Deterministic control evaluation
- Structured JSON output for reporting, dashboards or DRMF scoring
- Optional AI enrichment for gap interpretation and remediation advice
- Containerized execution for repeatable runs

---

## Architecture

```text
Microsoft Graph
      ↓
Graph Client
      ↓
Evaluators
      ↓
drmf_output.json
      ↓
AI Enricher
      ↓
drmf_enriched.json
```

### Data flow

| Stage | Description | Output |
|---|---|---|
| Collector | Pulls raw evidence from Microsoft Graph and evaluates controls deterministically | `drmf_output.json` |
| AI Enricher | Optional post-processing step for interpretation and recommendations | `drmf_enriched.json` |
| Reporting | Uses deterministic and/or enriched output for dashboards, reports or tickets | external |

---

## Design Principles

### Deterministic core

The collector is designed to be reproducible and audit-friendly.

It does not rely on AI for:

- status calculation
- scoring
- compliance conclusions
- pass/fail decisions

The deterministic output should be treated as the authoritative evidence source.

### AI as advisory layer

The AI enricher is optional and post-processing only.

It never modifies:

- `status`
- `reason`
- `expected`
- `observed`
- `evidence`

It only adds an `ai` object with interpretation.

Example:

```json
{
  "ai": {
    "insight": "ASR policy exists but rule-level enforcement is not proven.",
    "gap_analysis": "The collector found policy evidence, but not setting-level Block mode validation.",
    "recommended_action": "Validate ASR rule configuration and enforce critical rules in Block mode.",
    "risk_priority": "high",
    "confidence_adjusted": "medium",
    "missing_evidence": [
      "Rule-level ASR mode",
      "Assignment scope",
      "Endpoint coverage"
    ]
  }
}
```

---

## Project Structure

```text
.
├── Dockerfile
├── docker-compose.yml
├── main.py
├── requirements.txt
├── .env.example
├── output/
└── drmf_collector/
    ├── __init__.py
    ├── graph_client.py
    ├── models.py
    ├── utils.py
    ├── registry.py
    ├── ai_enricher.py
    └── evaluators/
        ├── __init__.py
        ├── apps.py
        ├── auth_methods.py
        ├── cross_tenant.py
        ├── entra.py
        ├── governance.py
        ├── identity_protection.py
        ├── intune.py
        ├── intune_expanded.py
        ├── named_locations.py
        ├── oauth_apps.py
        └── pim.py
```

---

## Components

### `graph_client.py`

Minimal Microsoft Graph REST client.

Provides:

- OAuth2 client credentials authentication
- token caching
- GET requests
- paging via `@odata.nextLink`
- basic retry logic for throttling and transient failures

### `models.py`

Defines the output model.

Main object:

```python
ControlResult
```

Important fields:

| Field | Purpose |
|---|---|
| `control_id` | DRMF control identifier |
| `title` | Control title |
| `status` | `pass`, `fail`, `partial`, or `error` |
| `confidence` | `low`, `medium`, or `high` |
| `reason` | Why the control received this status |
| `expected` | Expected secure/control state |
| `observed` | What was actually observed |
| `evidence` | Structured raw/derived evidence |
| `remediation_hint` | Recommended technical follow-up |
| `notes` | Known limitations or nuance |

### `registry.py`

Central registry of all enabled evaluators.

New checks are activated by importing and adding evaluator functions to:

```python
CONTROL_EVALUATORS
```

### `evaluators/`

Contains domain-specific control evaluation logic.

| File | Scope |
|---|---|
| `entra.py` | Conditional Access, MFA, risk policies, security defaults |
| `auth_methods.py` | Authentication Methods Policy |
| `apps.py` | Admin consent workflow, app registration restrictions |
| `oauth_apps.py` | OAuth app governance |
| `cross_tenant.py` | Cross-tenant access settings |
| `named_locations.py` | Conditional Access named locations |
| `governance.py` | Access Reviews |
| `pim.py` | Privileged Identity Management |
| `intune.py` | BitLocker escrow |
| `intune_expanded.py` | Intune policy-presence checks |
| `identity_protection.py` | Risky users and risk detections |

### `ai_enricher.py`

Optional AI post-processing layer.

Adds advisory interpretation to deterministic results.

---

## Current Control Coverage

The collector currently includes checks for the following control areas.

### Identity and Access

- MFA enforced for all users
- MFA enforced for admin roles
- Legacy authentication blocking indication
- PIM evidence for privileged roles
- Break-glass CA exclusion/monitoring indication
- Compliant device requirement via Conditional Access
- Phishing-resistant MFA indication for admins
- Sign-in risk and user risk policies
- Authentication Methods Policy hardening
- Security Defaults versus Conditional Access baseline

### App Governance

- Admin consent workflow
- Application registration restrictions
- OAuth app governance indicators

### External Access

- Cross-tenant access settings
- Named locations

### Identity Governance

- Access Review definitions
- Recurring Access Review evidence

### Endpoint / Intune

- MDE onboarding evidence indication
- ASR policy presence
- BitLocker recovery key escrow
- Windows LAPS policy presence
- Local admin restriction policy presence
- Compliance policy evidence
- Defender Firewall policy presence
- Network/Web protection policy presence
- Device Control policy presence
- Windows update rings/profile evidence
- Defender Antivirus cloud protection policy presence
- Security baseline-like policy presence
- MAM/BYOD app protection evidence

### Monitoring / Detection

- Identity Protection risky users
- Risk detections
- Recent sign-in sample availability

---

## Output Model

### Deterministic output

The main collector writes:

```text
output/drmf_output.json
```

Example:

```json
{
  "control_id": "ID-17",
  "title": "Access Reviews scheduled and enforced",
  "status": "fail",
  "confidence": "medium",
  "reason": "No Access Review definitions were found in Entra Identity Governance.",
  "expected": "Recurring Access Reviews exist for guests and/or privileged roles, with reviewers, recurrence, decisions, and enforcement configured.",
  "observed": "definition_count=0; scheduled_reviews=[]",
  "evidence": {
    "definition_count": 0,
    "scheduled_review_count": 0,
    "scheduled_reviews": [],
    "unscheduled_reviews": []
  },
  "timestamp_utc": "2026-05-04T06:01:06.788533+00:00",
  "source": "graph",
  "remediation_hint": "Create recurring Access Reviews under Entra Identity Governance for guest access and privileged role assignments.",
  "notes": "This check confirms scheduling evidence only. Completion quality and reviewer decisions require additional review."
}
```

### AI-enriched output

The optional AI enricher writes:

```text
output/drmf_enriched.json
```

Example:

```json
{
  "control_id": "ID-17",
  "status": "fail",
  "reason": "No Access Review definitions were found in Entra Identity Governance.",
  "ai": {
    "insight": "There is no Graph evidence that Access Reviews are configured.",
    "gap_analysis": "The tenant lacks Access Review definitions, so guest or privileged role reviews cannot be proven.",
    "recommended_action": "Create recurring Access Reviews for guest access and privileged role assignments.",
    "risk_priority": "medium",
    "confidence_adjusted": "medium",
    "missing_evidence": [
      "Access Review definitions",
      "Review recurrence",
      "Reviewer assignment",
      "Decision enforcement"
    ]
  }
}
```

---

## Status Semantics

| Status | Meaning |
|---|---|
| `pass` | Evidence indicates the control is implemented for the evaluated condition |
| `partial` | Some evidence exists, but scope, enforcement or completeness is not proven |
| `fail` | Expected evidence was not found |
| `error` | The evaluator could not complete due to API, permission or runtime error |

Important:

```text
partial is not a failure by definition.
partial means the collector cannot fully prove the control state from current evidence.
```

---

## Requirements

### Runtime

- Docker
- Docker Compose
- Microsoft Entra app registration
- Microsoft Graph application permissions
- Optional: OpenAI API key for AI enrichment

### Python dependencies

```text
requests>=2.32.0,<3.0.0
openai>=1.0.0,<2.0.0
```

---

## Microsoft Entra App Registration

Create an app registration:

```text
Microsoft Entra admin center
→ Identity
→ Applications
→ App registrations
→ New registration
```

Recommended name:

```text
drmf-graph-collector
```

Use:

```text
Accounts in this organizational directory only
```

No redirect URI is required.

Create a client secret:

```text
Certificates & secrets
→ Client secrets
→ New client secret
```

Copy:

- Tenant ID
- Client ID
- Client Secret value

---

## Required Microsoft Graph Permissions

The required permissions depend on enabled evaluators.

Recommended read-only starting set:

```text
Policy.Read.All
Directory.Read.All
AuditLog.Read.All
IdentityRiskyUser.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
DeviceManagementApps.Read.All
Application.Read.All
RoleManagement.Read.Directory
AccessReview.Read.All
BitlockerKey.Read.All
```

Grant admin consent after adding permissions. Use application permissions, not delegated permissions.

---

## Configuration

Create `.env` from the example:

```bash
cp .env.example .env
```

Example:

```env
TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
CLIENT_SECRET=replace-me

OUTPUT_PATH=/output/drmf_output.json
GRAPH_BASE_URL=https://graph.microsoft.com/v1.0

OPENAI_API_KEY=replace-me
OPENAI_MODEL=gpt-4.1-mini
AI_BATCH_SIZE=8
AI_INPUT_PATH=/output/drmf_output.json
AI_OUTPUT_PATH=/output/drmf_enriched.json
```

For collector-only usage, OpenAI variables are not required.

---

## Docker Usage

### Build

```bash
docker compose build --no-cache
```

### Run deterministic collector

```bash
docker compose run --rm drmf-graph-collector
```

Output:

```text
output/drmf_output.json
```

### Run AI enricher

```bash
docker compose run --rm drmf-ai-enricher
```

Output:

```text
output/drmf_enriched.json
```

Recommended sequence:

```bash
docker compose run --rm drmf-graph-collector
docker compose run --rm drmf-ai-enricher
```

---

## Docker Compose Example

```yaml
services:
  drmf-graph-collector:
    build:
      context: .
      dockerfile: Dockerfile
    image: drmf-graph-collector:latest
    container_name: drmf-graph-collector
    env_file:
      - .env
    environment:
      OUTPUT_PATH: /output/drmf_output.json
      GRAPH_BASE_URL: https://graph.microsoft.com/v1.0
    volumes:
      - ./output:/output
    restart: "no"
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL

  drmf-ai-enricher:
    build:
      context: .
      dockerfile: Dockerfile
    image: drmf-graph-collector:latest
    container_name: drmf-ai-enricher
    env_file:
      - .env
    environment:
      AI_INPUT_PATH: /output/drmf_output.json
      AI_OUTPUT_PATH: /output/drmf_enriched.json
      OPENAI_MODEL: ${OPENAI_MODEL:-gpt-4.1-mini}
      AI_BATCH_SIZE: ${AI_BATCH_SIZE:-8}
    volumes:
      - ./output:/output
    restart: "no"
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    entrypoint:
      - python
      - -m
      - drmf_collector.ai_enricher
```

---

### Batching

The AI enricher processes controls in batches.

Default:

```env
AI_BATCH_SIZE=8
```

Guidance:

| Scenario | Batch size |
|---|---|
| Large evidence payloads | 3–5 |
| Default | 8 |
| Cost-optimized | 10–15 |

### Smart filtering recommendation

AI enrichment is most useful for:

```text
status in ["fail", "partial"]
```

Successful deterministic `pass` controls usually do not require enrichment.

Recommended future filter logic:

```python
def should_enrich(control: dict) -> bool:
    if control["status"] == "fail":
        return True

    if control["status"] == "partial":
        if control.get("confidence") in ["low", "medium"]:
            return True

    return False
```

---

## Adding a New Control

### 1. Create evaluator

Add a function in the relevant evaluator file, for example:

```text
drmf_collector/evaluators/entra.py
```

Example:

```python
def evaluate_new_control(client: GraphClient) -> ControlResult:
    data = client.list_all("some/graph/endpoint")

    return result(
        control_id="ID-99",
        title="New control title",
        status="partial",
        confidence="medium",
        reason="Evidence exists, but enforcement is not fully proven.",
        expected="Expected secure state.",
        observed=f"items_found={len(data)}",
        evidence={"sample": data[:10]},
        remediation_hint="Recommended action.",
        notes="Known limitation.",
    )
```

### 2. Register evaluator

Add it to:

```text
drmf_collector/registry.py
```

Example:

```python
from .evaluators.entra import evaluate_new_control

CONTROL_EVALUATORS = [
    evaluate_new_control,
]
```

### 3. Rebuild

```bash
docker compose build --no-cache
```

### 4. Run

```bash
docker compose run --rm drmf-graph-collector
```

---

### Local Python run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py
```

### Container run

```bash
docker compose build --no-cache
docker compose run --rm drmf-graph-collector
```

### Validate imports

```bash
python -m compileall .
```

### Inspect container contents

```bash
docker compose run --rm --entrypoint sh drmf-graph-collector -c \
"find /app/drmf_collector/evaluators -maxdepth 1 -type f -print"
```

---

## Troubleshooting

### `ModuleNotFoundError`

Example:

```text
No module named 'drmf_collector.evaluators.intune_expanded'
```

Cause:

The file is not located in:

```text
drmf_collector/evaluators/intune_expanded.py
```

Fix:

```bash
find . -name "intune_expanded.py" -print
```

Expected:

```text
./drmf_collector/evaluators/intune_expanded.py
```

Rebuild:

```bash
docker compose build --no-cache
```

---

## Known Limitations

### Graph is not complete coverage

Some Microsoft security settings are better queried through other APIs:

| Area | Better source |
|---|---|
| Exchange SMTP AUTH / DKIM / mailbox audit | Exchange Online PowerShell |
| Defender XDR advanced features | Defender APIs / Defender portal |
| Purview DLP / retention / eDiscovery | Purview APIs / portal exports |
| Azure resource posture | ARM / Azure Resource Graph |
| DNS records | DNS provider |
