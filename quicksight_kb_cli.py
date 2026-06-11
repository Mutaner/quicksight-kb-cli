#!/usr/bin/env python3
"""
quicksight_kb_cli.py — QuickSight Knowledge Base CLI

CLI tool for Amazon QuickSight Knowledge Bases (June 2026 API).

Commands:
  create-kb   — Create a knowledge base (direct SigV4 REST call)
  list-kbs    — List knowledge bases in the account
  delete-kb   — Delete a knowledge base by ID

Note: CreateKnowledgeBase is not yet in boto3 — this tool uses raw SigV4 signing.

Dependencies: boto3>=1.43.25 (pip install -r requirements.txt)

Examples:
  python3 quicksight_kb_cli.py --region us-east-1 --aws-account-id 123456789012 list-kbs
  python3 quicksight_kb_cli.py --region us-east-1 --aws-account-id 123456789012 create-kb \\
      --name "My KB" --type SHAREPOINT --data-source-arn "arn:aws:..."
  python3 quicksight_kb_cli.py --region us-east-1 --aws-account-id 123456789012 delete-kb --id kb-abc123
"""

import argparse
import hashlib
import hmac
import json
import logging
import sys
import textwrap
import traceback
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ParamValidationError,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SERVICE_NAME = "quicksight"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

BOTO_TIMEOUT_CONFIG = BotoConfig(
    connect_timeout=10,
    read_timeout=30,
    retries={"max_attempts": 3},
)

# ---------------------------------------------------------------------------
# Error formatting
# ---------------------------------------------------------------------------


def _friendly_error(msg: str, detail: str = "") -> str:
    parts = [f"[ERROR] {msg}"]
    if detail:
        parts.append(detail)
    return "\n".join(parts)


def _handle_boto3_error(e: Exception) -> str:
    if isinstance(e, NoCredentialsError):
        return _friendly_error(
            "AWS credentials not found.",
            "Check ~/.aws/credentials or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.",
        )
    if isinstance(e, NoRegionError):
        return _friendly_error(
            "AWS region not specified.",
            "Pass --region or set AWS_DEFAULT_REGION.",
        )
    if isinstance(e, ParamValidationError):
        return _friendly_error("Parameter validation failed.", str(e))
    if isinstance(e, ClientError):
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        hints = {
            "AccessDeniedException": "Permission denied. Check IAM policy.",
            "ResourceNotFoundException": "Resource not found.",
            "ValidationException": "Invalid input data.",
            "ThrottlingException": "Rate limit exceeded. Retry with backoff.",
            "InternalServerException": "AWS internal error. Retry later.",
            "ConflictException": "Resource with this name already exists.",
        }
        hint = hints.get(code, f"AWS error code: {code}")
        return _friendly_error(f"AWS returned an error (HTTP {status})", f"{hint}\nDetails: {message}")
    if isinstance(e, BotoCoreError):
        return _friendly_error("Internal boto3 error.", str(e))
    return _friendly_error(
        f"Unknown error ({type(e).__name__})",
        str(e) if str(e) else traceback.format_exc(),
    )


# ---------------------------------------------------------------------------
# SigV4 signing for direct REST calls (CreateKnowledgeBase not in boto3)
# ---------------------------------------------------------------------------


def _sigv4_sign(
    method: str,
    host: str,
    path: str,
    region: str,
    service: str,
    access_key: str,
    secret_key: str,
    session_token: str,
    body: bytes = b"",
    query_params: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Sign an HTTP request using AWS Signature V4 and return headers."""
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    canonical_uri = path
    canonical_querystring = ""
    if query_params:
        canonical_querystring = urllib.parse.urlencode(sorted(query_params.items()))
    payload_hash = hashlib.sha256(body).hexdigest()

    headers: Dict[str, str] = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    signed_headers = ";".join(sorted(headers.keys()))

    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    def _hmac(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

    k_date = _hmac(f"AWS4{secret_key}".encode(), date_stamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    k_signing = _hmac(k_service, "aws4_request")
    signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth_header = f"{algorithm} Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
    headers["Authorization"] = auth_header
    headers["Content-Type"] = "application/json"

    return headers


def _rest_call(
    method: str,
    path: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str,
    body: Optional[Dict[str, Any]] = None,
    query_params: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Execute a REST call to the QuickSight API with SigV4 signing."""
    host = f"quicksight.{region}.amazonaws.com"
    url = f"https://{host}{path}"
    payload = json.dumps(body).encode() if body else b""

    signed_headers = _sigv4_sign(
        method=method,
        host=host,
        path=path,
        region=region,
        service="quicksight",
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        body=payload,
        query_params=query_params,
    )

    try:
        req = urllib.request.Request(url, data=payload or None, headers=signed_headers, method=method)
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read().decode()
            result = json.loads(raw) if raw else {}
            result["_http_status"] = resp.status
            return result
    except urllib.error.HTTPError as e:
        body_raw = e.read().decode()
        try:
            err_body = json.loads(body_raw)
        except json.JSONDecodeError:
            err_body = {"message": body_raw}
        raise RuntimeError(
            f"REST call returned HTTP {e.code}: {err_body.get('message', json.dumps(err_body, ensure_ascii=False))}"
        )
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error: {e.reason}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_empty_listing(result: Any, action: str) -> bool:
    if action not in ("list-kbs",):
        return False
    if not isinstance(result, dict):
        return False
    for key in ("KnowledgeBaseSummaries",):
        if key in result and isinstance(result[key], list) and len(result[key]) == 0:
            return True
    return False


def _setup_debug_logging() -> None:
    """Enable boto3 debug logging via modern API.

    WARNING: Debug mode may print AWS credentials to stdout/stderr.
    Only use in isolated environments.
    """
    print("[WARNING] Debug mode enabled. AWS credentials may appear in logs.", file=sys.stderr)
    logging.basicConfig(level=logging.DEBUG)
    for logger_name in ("boto3", "botocore", "s3transfer", "urllib3"):
        logging.getLogger(logger_name).setLevel(logging.DEBUG)
        logging.getLogger(logger_name).propagate = True


# ---------------------------------------------------------------------------
# Action functions
# ---------------------------------------------------------------------------


def action_create_kb(
    client: boto3.client,
    args: argparse.Namespace,
    session: boto3.Session,          # <-- теперь сессия передаётся явно
) -> Dict[str, Any]:
    """
    Создать базу знаний QuickSight.
    CreateKnowledgeBase нет в текущем boto3 — используем прямой REST-запрос.
    """
    if not args.data_source_arn:
        raise ValueError(
            _friendly_error(
                "Не указан DataSourceArn.",
                "--data-source-arn обязателен для create-kb.",
            )
        )

    creds = session.get_credentials()
    if creds is None:
        raise ValueError(
            _friendly_error(
                "Учётные данные AWS не найдены.",
                "Проверьте ~/.aws/credentials или AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.",
            )
        )
    frozen = creds.get_frozen_credentials()

    region = args.region or session.region_name
    if region is None:
        raise ValueError(
            _friendly_error(
                "Регион AWS не указан.",
                "Передайте --region или установите AWS_DEFAULT_REGION.",
            )
        )

    path = f"/v1/accounts/{args.aws_account_id}/knowledge-bases/"
    body: Dict[str, Any] = {
        "Name": args.name,
        "Type": args.type,
        "DataSourceArn": args.data_source_arn,
    }
    if args.source_uri:
        body["SourceUri"] = args.source_uri

    return _rest_call(
        method="POST",
        path=path,
        region=region,
        access_key=frozen.access_key,
        secret_key=frozen.secret_key,
        session_token=frozen.token or "",
        body=body,
    )


def cmd_list_kbs(client: boto3.client, args: argparse.Namespace) -> Dict[str, Any]:
    """List all knowledge bases."""
    kwargs: Dict[str, Any] = {"AwsAccountId": args.aws_account_id}
    if args.max_results:
        kwargs["MaxResults"] = args.max_results
    if args.starting_token:
        kwargs["NextToken"] = args.starting_token

    return client.list_knowledge_bases(**kwargs)


def cmd_delete_kb(client: boto3.client, args: argparse.Namespace) -> Dict[str, Any]:
    """Delete a knowledge base by ID."""
    return client.delete_knowledge_base(
        AwsAccountId=args.aws_account_id,
        KnowledgeBaseId=args.id,
    )


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quicksight-kb-cli",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            CLI tool for QuickSight Knowledge Bases (June 2026).

            Requires Python >= 3.10 and boto3 >= 1.43.25.
            Install: pip install -r requirements.txt

            AWS credentials: ~/.aws/credentials or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.
        """),
        epilog=textwrap.dedent("""\
            Examples:
              # Create a knowledge base
              python3 quicksight_kb_cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 create-kb \\
                  --name "Support KB" --type SHAREPOINT \\
                  --data-source-arn arn:aws:quicksight:us-east-1:123456789012:datasource/xxx

              # List all knowledge bases (with pagination)
              python3 quicksight_kb_cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 list-kbs --max-results 20

              # Delete a knowledge base
              python3 quicksight_kb_cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 delete-kb --id kb-abc123
        """),
    )

    parser.add_argument("--region", default=None, help="AWS region")
    parser.add_argument("--profile", default=None, help="Profile from ~/.aws/credentials")
    parser.add_argument("--aws-account-id", required=True,
                        help="12-digit AWS Account ID (e.g. 123456789012)")

    # Validate aws-account-id format after parsing
    def _validate_account_id(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        import re
        if not re.fullmatch(r"\d{12}", args.aws_account_id):
            parser.error("--aws-account-id must be exactly 12 digits (e.g. 123456789012)")

    _validate_account_id(parser, parser.parse_known_args()[0])
    parser.add_argument("--endpoint-url", default=None, help="Custom endpoint (debugging)")
    parser.add_argument("--debug", action="store_true", help="Enable boto3 debug logging")

    subparsers = parser.add_subparsers(dest="action", required=True, help="Available actions")

    # create-kb
    create_parser = subparsers.add_parser("create-kb", help="Create a knowledge base")
    create_parser.add_argument("--name", required=True, help="Knowledge base name")
    create_parser.add_argument(
        "--type", required=True,
        choices=["SHAREPOINT", "S3", "SALESFORCE", "SERVICENOW", "JIRA", "CONFLUENCE", "CUSTOM"],
        help="Data source type",
    )
    create_parser.add_argument("--source-uri", default=None, help="Source URI (e.g. SharePoint URL)")
    create_parser.add_argument(
        "--data-source-arn", required=True,
        help="QuickSight data source ARN (arn:aws:quicksight:...:datasource/...)",
    )

    # list-kbs
    list_parser = subparsers.add_parser("list-kbs", help="List knowledge bases")
    list_parser.add_argument("--max-results", type=int, default=None, help="Max results")
    list_parser.add_argument("--starting-token", default=None, help="Pagination token")

    # delete-kb
    del_parser = subparsers.add_parser("delete-kb", help="Delete a knowledge base")
    del_parser.add_argument("--id", required=True, help="Knowledge base ID (KnowledgeBaseId)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    session_kwargs: Dict[str, Any] = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region

    try:
        session = boto3.Session(**session_kwargs)
    except Exception as e:
        print(_friendly_error("Failed to create AWS session.", str(e)), file=sys.stderr)
        return EXIT_FAILURE

    client_kwargs: Dict[str, Any] = {
        "service_name": SERVICE_NAME,
        "config": BOTO_TIMEOUT_CONFIG,
    }
    if args.endpoint_url:
        client_kwargs["endpoint_url"] = args.endpoint_url
    if args.debug:
        print("[WARNING] Debug mode enabled. AWS credentials may appear in output. Use only in isolated environments.", file=sys.stderr)
        _setup_debug_logging()

    try:
        client = session.client(**client_kwargs)
    except Exception as e:
        print(_friendly_error("Failed to create boto3 client.", str(e)), file=sys.stderr)
        return EXIT_FAILURE

    # Wrapper to dispatch commands: create-kb needs session, others don't
    def _dispatch(action: str) -> Dict[str, Any]:
        if action == "create-kb":
            return cmd_create_kb(client, args, session)
        elif action == "list-kbs":
            return cmd_list_kbs(client, args)
        elif action == "delete-kb":
            return cmd_delete_kb(client, args)
        else:
            raise ValueError(f"Unknown action: {action}")

    try:
        result = _dispatch(args.action)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return EXIT_FAILURE
    except Exception as e:
        print(_handle_boto3_error(e), file=sys.stderr)
        return EXIT_FAILURE

    preview = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if _is_empty_listing(result, args.action):
        print("[INFO] No resources found. API returned an empty list.", file=sys.stderr)
    print(preview)
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())