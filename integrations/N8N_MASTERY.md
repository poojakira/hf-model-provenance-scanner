# n8n Workflow Mastery  --  ML Security Automation

Production-grade n8n workflow orchestration for ML security operations. Three import-ready workflows covering the full incident lifecycle: detection → triage → enrichment → response → containment.

## Workflows

| Workflow | Nodes | Purpose | File |
|----------|-------|---------|------|
| Model Scan Pipeline | 8 | Webhook → scan → severity routing → alert → quarantine | `n8n-model-scan-pipeline.json` |
| IAM Posture Scan | 8 | Cron → live scan → parse → route → alert → ticket | `n8n-iam-posture-scan.json` |
| **SOC Incident Pipeline** | **18** | **Multi-source ingest → dedup → enrich → route → page → auto-remediate** | `n8n-soc-incident-pipeline.json` |

## Architecture: SOC Incident Pipeline

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        ML Security SOC Pipeline                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                               │
│  ┌──────────┐   ┌───────────┐   ┌───────┐   ┌──────────┐   ┌────────────┐ │
│  │ Webhook  │──▶│ Normalize │──▶│ Redis │──▶│ Enrich & │──▶│  Route by  │ │
│  │ Ingest   │   │  Event    │   │ Dedup │   │  Score   │   │  Priority  │ │
│  └──────────┘   └───────────┘   └───────┘   └──────────┘   └─────┬──────┘ │
│                                                                     │        │
│                    ┌────────────────────────────────────────────────┼────┐   │
│                    │                    │                            │    │   │
│               ▼ P1 (≥80)          ▼ P2 (≥50)                  ▼ P3 (<50)│   │
│  ┌─────────────────────┐  ┌──────────────────┐  ┌────────────────────┐ │   │
│  │ • PagerDuty page    │  │ • Slack #alerts  │  │ • Audit log only   │ │   │
│  │ • Slack #incidents  │  │ • Jira ticket    │  │ • No human action  │ │   │
│  │ • Auto-remediate?   │  │                  │  │                    │ │   │
│  │   ├─ Yes: Contain   │  └──────────────────┘  └────────────────────┘ │   │
│  │   │  (deny boundary)│                                                │   │
│  │   └─ No: Track only │                                                │   │
│  └─────────────────────┘                                                │   │
│                                                                          │   │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Advanced Capabilities Demonstrated

### 1. Multi-Source Event Normalization
The Code node detects event source by schema fingerprint and normalizes into a common format:
- HF Provenance Scanner findings (supply chain)
- AWS Agent Identity Guard reports (IAM posture)
- MCP Security Gateway alerts (tool-call monitoring)
- GuardDuty findings via EventBridge (AWS threat detection)
- Generic SARIF input (any code scanning tool)

### 2. Redis-Based Deduplication
Events are deduplicated with a 1-hour TTL Redis key. Duplicates get a `409 Conflict` webhook response. This prevents alert storms when the same finding fires repeatedly.

### 3. MITRE ATT&CK Enrichment
Each event is automatically mapped to ATT&CK techniques based on its source:
- Supply chain findings → T1195.002, T1059.006
- IAM findings → T1078.004, T1098, T1548
- MCP gateway → T1059, T1041, T1567
- GuardDuty → T1190, T1110

### 4. Priority Scoring & SLA Assignment
Events receive a 0-100 priority score based on severity × source reliability. SLAs are assigned automatically:
- Score ≥ 80 → P1 → 15 min SLA → Page on-call
- Score ≥ 50 → P2 → 60 min SLA → Slack + Jira
- Score < 50 → P3 → 8 hour SLA → Audit log only

### 5. Automated Containment (IAM)
For IAM findings scoring ≥ 85, the workflow auto-attaches a deny-all permission boundary to the offending role. This is:
- **Non-destructive**  --  the role still exists, policies are untouched
- **Immediately effective**  --  the boundary caps effective permissions to zero
- **Reversible**  --  security team removes the boundary after investigation
- **Audited**  --  containment action is logged and Slack-notified

### 6. Structured Webhook Response
The webhook returns immediately with the event ID and dedup status (200 or 409), enabling synchronous integration with upstream systems.

## Import & Setup

```bash
# Import all three workflows
n8n import:workflow --input integrations/n8n-model-scan-pipeline.json
n8n import:workflow --input integrations/n8n-iam-posture-scan.json
n8n import:workflow --input integrations/n8n-soc-incident-pipeline.json
```

### Required Infrastructure
- **n8n** (Community Edition, self-hosted, free)
- **Redis** (for deduplication cache  --  any instance, even `redis:alpine` in Docker)
- **Slack webhook** (free)
- **PagerDuty** (optional, for P1 paging)
- **Jira** (optional, for ticket creation)

### Environment Variables

```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
PAGERDUTY_EVENTS_URL=https://events.pagerduty.com/v2/enqueue
PAGERDUTY_ROUTING_KEY=your-service-routing-key
JIRA_BASE_URL=https://yourorg.atlassian.net
JIRA_PROJECT_KEY=MLSEC
QUARANTINE_API_URL=http://model-registry:8080
SCANNER_DASHBOARD_URL=https://scanner.internal.company.com
```

## Testing the Pipeline

Send a test event to verify the pipeline works end-to-end:

```bash
# Simulate a model supply chain alert
curl -X POST http://localhost:5678/webhook/security-event \
  -H "Content-Type: application/json" \
  -d '{
    "scan_target": "evil-corp/backdoored-llama",
    "findings": [
      {"rule_id": "HFS-001", "severity": "critical", "evidence": "pickle exec opcode detected"}
    ],
    "risk": {"level": "CRITICAL", "score": 95}
  }'

# Simulate an IAM posture finding
curl -X POST http://localhost:5678/webhook/security-event \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "AIG011",
    "severity": "critical",
    "resource_name": "compromised-agent-role",
    "message": "Agent has cloudtrail:StopLogging"
  }'

# Expected: 200 OK with event_id on first call, 409 Conflict on duplicate
```

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Redis dedup over DB | Sub-millisecond lookups, TTL auto-expiry, zero schema |
| Switch node over nested IF | Cleaner routing, easier to add P4/P5 paths later |
| Code nodes for enrichment | Complex logic (ATT&CK mapping) is cleaner in JS than node chains |
| Permission boundary for containment | Non-destructive, immediately effective, easily reversible |
| Webhook response before processing | Upstream doesn't timeout waiting for Slack/Jira calls |
| 1-hour dedup window | Balances: long enough to suppress storm, short enough to re-alert on new occurrence |

## Cost

$0. All components have free tiers or are self-hosted:
- n8n Community Edition: free, self-hosted
- Redis: `docker run redis:alpine` (50MB RAM)
- Slack webhooks: free
- PagerDuty: free tier (5 users)
- Jira: free tier (10 users)
