# QuickSight Knowledge Base CLI

**The first CLI for Amazon QuickSight Knowledge Bases — available day one.**

> ⚡ **June 2026**: AWS released 8 new Knowledge Base APIs for QuickSight. `boto3` has `list_knowledge_bases` and `delete_knowledge_base`, but **`CreateKnowledgeBase` isn't in the SDK yet**. This CLI fills the gap with a direct SigV4-signed REST call.

## Description

`quicksight-kb-cli` is a production-ready command-line tool for managing **Amazon QuickSight Knowledge Bases** — the new Q feature for grounding AI-generated answers in enterprise data (SharePoint, S3, Salesforce, ServiceNow, Jira, Confluence, and custom sources).

**Why this exists:** The June 2026 QuickSight release added 8 Knowledge Base APIs, but the `boto3` SDK only shipped 7 of them. `CreateKnowledgeBase` is missing. This tool implements the missing endpoint via raw SigV4-authenticated REST calls — no waiting for the SDK update.

### Features

- **create-kb** — Create a knowledge base (SigV4 REST, not in boto3 yet)
- **list-kbs** — List all knowledge bases in your AWS account (boto3)
- **delete-kb** — Delete a knowledge base by ID (boto3)
- **Zero-Traceback** — Every AWS error is parsed into clean, human-readable JSON
- **Network-safe** — 10s connect timeout, 30s read timeout, 3 retries on all calls
- **SigV4 built-in** — No extra dependencies for REST signing

## Installation

```bash
pip install "boto3>=1.43.25"
```

Python 3.10+ required. No additional dependencies — SigV4 is implemented with Python stdlib only (`hashlib`, `hmac`, `urllib`).

## Authentication

Credentials are resolved via the standard AWS credential chain:

```bash
# Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=*** AWS_DEFAULT_REGION=us-east-1

# Or: ~/.aws/credentials
# Or: IAM role on EC2/ECS/Lambda
```

The `--aws-account-id` flag is **required** for all operations (12-digit numeric ID).

## Usage

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
    list-kbs \
    --max-results 20
```

### Delete a knowledge base

```bash
python3 quicksight-kb-cli.py \
    --region us-east-1 \
    --aws-account-id 123456789012 \
    delete-kb \
    --id kb-abc123def456
```

### Additional options

| Flag | Description |
|------|-------------|
| `--profile` | AWS credential profile name |
| `--endpoint-url` | Custom API endpoint (debugging) |
| `--debug` | Enable boto3 debug logging |

## Error Handling

This tool never prints Python tracebacks. All errors are caught and displayed in structured format:

```
[ОШИБКА] Access denied. Check IAM permissions.
Details: User: arn:aws:iam::123456789012:user/admin is not authorized to perform: quicksight:CreateKnowledgeBase
```

Error types handled explicitly:

| AWS Error | User-friendly message |
|-----------|---------------------|
| `AccessDeniedException` | Permission denied — check IAM policy |
| `ResourceNotFoundException` | Resource not found |
| `ValidationException` | Invalid input data |
| `ThrottlingException` | Rate limit exceeded |
| `ConflictException` | Resource with this name already exists |
| `InternalServerException` | AWS internal error — retry later |

REST API errors (from the SigV4 path) are also wrapped in clean messages with HTTP status codes.

## Commercial Support

Need a Knowledge Base automation pipeline, cross-account deployment, or a custom integration with your data sources?

📧 **Email**: [alex.o.europe@gmail.com]  
🔧 **One-time setup**: $200–$600 per account  
📋 **Enterprise consulting**: Custom workflows, IAM policies, SharePoint/Salesforce connector tuning

This tool is part of the **AWS New-API Gap Filler** collection — bridging the gap between AWS API releases and community tooling since June 2026.

---

*Made for the Amazon QuickSight Knowledge Base API (June 2026 release)*
