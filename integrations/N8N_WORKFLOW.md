# n8n Workflow Integration

Import-ready n8n workflow for automated model security scanning.

## Pipeline: Model Upload → Scan → Alert → Quarantine

**File:** `integrations/n8n-model-scan-pipeline.json`

### What it does

1. **Webhook trigger** — receives POST from HuggingFace Hub, your model registry, or any system that publishes model upload events
2. **Provenance scan** — calls the scanner API against the uploaded model
3. **Risk routing** — if HIGH/CRITICAL findings, triggers the incident path; otherwise notifies success
4. **Incident path:**
   - Alerts `#ml-security-alerts` Slack channel with structured blocks (repo, risk level, top finding)
   - Quarantines the model via your registry API
   - Creates a Jira security incident ticket

### Import into n8n

```bash
# Self-hosted n8n
n8n import:workflow --input integrations/n8n-model-scan-pipeline.json

# Or via the n8n UI: Settings → Import from File
```

### Required credentials

| Credential | Environment Variable | Purpose |
|-----------|---------------------|---------|
| Slack webhook | `SLACK_WEBHOOK_URL` | Alert channel |
| Jira API | `JIRA_BASE_URL`, `JIRA_PROJECT_KEY` | Ticket creation |
| Quarantine API | `QUARANTINE_API_URL` | Model isolation |
| Scanner dashboard | `SCANNER_DASHBOARD_URL` | Link in alerts |

### Required: Scanner API running

The workflow calls `http://localhost:8000/scan` — the scanner's FastAPI endpoint. Start it:

```bash
uvicorn scanner.api:app --host 0.0.0.0 --port 8000
```

Or point the workflow at your deployed scanner URL.

### Trigger format

POST to the webhook with:

```json
{
  "repo_id": "organization/model-name",
  "revision": "abc123def456"
}
```

### Customization

- Adjust the severity threshold in the "High/Critical Findings?" node
- Add PagerDuty/OpsGenie nodes for on-call escalation
- Add an S3 upload node to archive SARIF reports
- Chain with the IAM scanner workflow for full posture assessment

## Zero-cost deployment

n8n Community Edition is self-hosted and free. Run it alongside the scanner:

```bash
docker run -d --name n8n \
  -p 5678:5678 \
  -v n8n_data:/home/node/.n8n \
  -e N8N_SECURE_COOKIE=false \
  n8nio/n8n
```

Then import the workflow and configure credentials in the n8n UI.
