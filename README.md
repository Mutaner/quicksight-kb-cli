# QuickSight Knowledge Base CLI

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![AWS](https://img.shields.io/badge/aws-quicksight-orange.svg)

**The first CLI for Amazon QuickSight Knowledge Bases — available day one.**

> ⚡ **June 2026**: AWS released 8 new Knowledge Base APIs for QuickSight.
> `boto3` ships `list_knowledge_bases` and `delete_knowledge_base`, but
> **`CreateKnowledgeBase` isn't in the SDK yet**. This CLI fills the gap
> with a direct SigV4-signed REST call.

## Description

`quicksight-kb-cli` is a production-ready command-line tool for managing
**Amazon QuickSight Knowledge Bases** — the new Q feature for grounding AI
answers in enterprise data (SharePoint, S3, Salesforce, ServiceNow, Jira,
Confluence, and custom sources).

### Features

- **create-kb** — Create a knowledge base via SigV4 REST (not in boto3 yet)
- **list-kbs** — List all knowledge bases in your AWS account
- **delete-kb** — Delete a knowledge base by ID
- **Zero-Traceback** — Every AWS error is parsed into clean output
- **Network-safe** — 10s connect timeout, 30s read timeout, 3 retries
- **SigV4 built-in** — Python stdlib only (`hashlib`, `hmac`, `urllib`)

## Installation

```bash
pip install -r requirements.txt
```

Python 3.10+ required. No extra dependencies — SigV4 uses Python stdlib.

## Quick Start

### Create a knowledge base (REST API — not in boto3)

```bash
python3 quicksight-kb-cli.py \
    --region us-east-1 \
    --aws-account-id 123456789012 \
    create-kb \
    --name "Customer Support KB" \
    --type SHAREPOINT \
    --data-source-arn arn:aws:quicksight:us-east-1:123456789012:datasource/ds-abc123 \
    --source-uri "https://contoso.sharepoint.com/sites/support"
```

Supported `--type` values:

| Type | Description |
|------|-------------|
| `SHAREPOINT` | Microsoft SharePoint Online |
| `S3` | Amazon S3 |
| `SALESFORCE` | Salesforce CRM |
| `SERVICENOW` | ServiceNow |
| `JIRA` | Atlassian Jira |
| `CONFLUENCE` | Atlassian Confluence |
| `CUSTOM` | Custom data source |

### List all knowledge bases

```bash
python3 quicksight-kb-cli.py \
    --region us-east-1 \
    --aws-account-id 123456789012 \
    list-kbs --max-results 20
```

### Delete a knowledge base

```bash
python3 quicksight-kb-cli.py \
    --region us-east-1 \
    --aws-account-id 123456789012 \
    delete-kb --id kb-abc123def456
```

### Pipe through `jq`

```bash
python3 quicksight-kb-cli.py \
    --region us-east-1 --aws-account-id 123456789012 list-kbs \
    | jq '.KnowledgeBaseSummaries[] | {name: .Name, status: .Status, type: .Type}'
```

### Example JSON output

```json
{
  "KnowledgeBaseSummaries": [
    {
      "KnowledgeBaseId": "kb-abc123def456",
      "Name": "Customer Support KB",
      "Status": "ACTIVE",
      "Type": "SHAREPOINT",
      "DataSourceArn": "arn:aws:quicksight:...",
      "DocumentCount": 1520,
      "CreatedAt": "2026-06-10T12:00:00Z"
    }
  ],
  "NextToken": null
}
```

## Authentication

Standard AWS credential chain:

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Or: ~/.aws/credentials
# Or: IAM role on EC2/ECS/Lambda
```

The `--aws-account-id` flag is **required** for all operations (12-digit numeric ID).

## CLI Options

| Flag | Description |
|------|-------------|
| `--region` | AWS region |
| `--aws-account-id` | 12-digit AWS account ID (required) |
| `--profile` | AWS credential profile |
| `--endpoint-url` | Custom API endpoint (debugging) |
| `--debug` | Enable debug logging |

## Error Handling

No Python tracebacks. All errors are parsed to clean output:

```text
[ОШИБКА] Access denied. Check IAM permissions.
Details: User: arn:aws:iam::... is not authorized to perform: quicksight:CreateKnowledgeBase
```

| AWS Error | User-friendly message |
|-----------|----------------------|
| `AccessDeniedException` | Permission denied — check IAM policy |
| `ResourceNotFoundException` | Resource not found |
| `ValidationException` | Invalid input data |
| `ThrottlingException` | Rate limit exceeded |
| `ConflictException` | Resource with this name already exists |
| `InternalServerException` | AWS internal error — retry later |

REST API errors (SigV4 path) are wrapped with HTTP status codes.

## Contact & Support

Questions, feature requests, or enterprise integrations?

📧 **alex.o.europe@gmail.com**

---

*Part of the AWS New-API Gap Filler collection — June 2026.*