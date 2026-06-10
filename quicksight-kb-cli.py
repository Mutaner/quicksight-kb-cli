#!/usr/bin/env python3
"""
quicksight-kb-cli.py — QuickSight Knowledge Base CLI

CLI tool for Amazon QuickSight Knowledge Bases (June 2026 API).

Commands:
  create-kb   — Create a knowledge base (direct SigV4 REST call)
  list-kbs    — List knowledge bases in the account
  delete-kb   — Delete a knowledge base by ID

Note: CreateKnowledgeBase is not yet in boto3 — this tool uses raw SigV4 signing.

Dependencies: boto3>=1.43.25 (pip install -r requirements.txt)

Examples:
  python3 quicksight-kb-cli.py --region us-east-1 --aws-account-id 123456789012 list-kbs
  python3 quicksight-kb-cli.py --region us-east-1 --aws-account-id 123456789012 create-kb \\
      --name "My KB" --type SHAREPOINT --data-source-arn "arn:aws:..."
  python3 quicksight-kb-cli.py --region us-east-1 --aws-account-id 123456789012 delete-kb --id kb-abc123
"""

import argparse
import json
import sys
import textwrap
import traceback
import hashlib
import hmac
import urllib.request
import urllib.error
from datetime import datetime, timezone

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    NoRegionError,
    ParamValidationError,
)

# Типы для type hints (Python 3.10+)
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------
SERVICE_NAME = "quicksight"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

# Таймауты для boto3-клиента (сек)
BOTO_TIMEOUT_CONFIG = BotoConfig(
    connect_timeout=10,
    read_timeout=30,
    retries={"max_attempts": 3},
)


# ---------------------------------------------------------------------------
# Форматирование ошибок
# ---------------------------------------------------------------------------

def _friendly_error(msg: str, detail: str = "") -> str:
    parts = [f"[ОШИБКА] {msg}"]
    if detail:
        parts.append(detail)
    return "\n".join(parts)


def _handle_boto3_error(e: Exception) -> str:
    if isinstance(e, NoCredentialsError):
        return _friendly_error(
            "Учётные данные AWS не найдены.",
            "Проверьте ~/.aws/credentials или AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.",
        )
    if isinstance(e, NoRegionError):
        return _friendly_error(
            "Регион AWS не указан.",
            "Передайте --region или установите AWS_DEFAULT_REGION.",
        )
    if isinstance(e, ParamValidationError):
        return _friendly_error("Ошибка валидации параметров.", str(e))
    if isinstance(e, ClientError):
        code = e.response["Error"]["Code"]
        message = e.response["Error"]["Message"]
        status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        hints = {
            "AccessDeniedException": "Доступ запрещён. Проверьте IAM-права.",
            "ResourceNotFoundException": "Указанный ресурс не найден.",
            "ValidationException": "Ошибка валидации входных данных.",
            "ThrottlingException": "Превышен лимит запросов.",
            "InternalServerException": "Внутренняя ошибка AWS.",
            "ConflictException": "Конфликт: ресурс с таким именем уже существует.",
        }
        hint = hints.get(code, f"Код ошибки AWS: {code}")
        return _friendly_error(f"AWS вернул ошибку (HTTP {status})", f"{hint}\nДетали: {message}")
    if isinstance(e, BotoCoreError):
        return _friendly_error("Внутренняя ошибка boto3.", str(e))
    return _friendly_error(f"Неизвестная ошибка ({type(e).__name__})", str(e) if str(e) else traceback.format_exc())


# ---------------------------------------------------------------------------
# SigV4-подпись для прямых REST-запросов (CreateKnowledgeBase нет в boto3)
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
) -> dict:
    """Подписывает HTTP-запрос по AWS Signature V4 и возвращает headers."""
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")

    # Канонический запрос
    canonical_uri = path
    canonical_querystring = ""
    payload_hash = hashlib.sha256(body).hexdigest()

    headers = {
        "host": host,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if session_token:
        headers["x-amz-security-token"] = session_token

    canonical_headers = "".join(f"{k}:{v}\n" for k, v in sorted(headers.items()))
    signed_headers = ";".join(sorted(headers.keys()))

    canonical_request = f"{method}\n{canonical_uri}\n{canonical_querystring}\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

    # String to sign
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = f"{algorithm}\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"

    # Signing key
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
    body: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Выполняет REST-запрос к QuickSight API с SigV4-подписью."""
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
            f"REST-запрос вернул HTTP {e.code}: {err_body.get('message', json.dumps(err_body, ensure_ascii=False))}"
        )
    except urllib.error.URLError as e:
        raise RuntimeError(f"Сетевая ошибка: {e.reason}")


# ---------------------------------------------------------------------------
# Функции-действия
# ---------------------------------------------------------------------------


def _is_empty_listing(result: Any, action: str) -> bool:
    """Проверяет, вернул ли API пустой список для операций листинга.

    Проверяет ключи: Sessions, KnowledgeBaseSummaries, Flows, Ids.
    Возвращает True, если такой ключ есть и значение — пустой список.
    """
    if action not in ("list-sessions", "list-kbs", "list-flows"):
        return False
    if not isinstance(result, dict):
        return False
    for key in ("Sessions", "KnowledgeBaseSummaries", "Flows", "Ids"):
        if key in result and isinstance(result[key], list) and len(result[key]) == 0:
            return True
    return False


def action_create_kb(client: boto3.client, args: argparse.Namespace) -> Dict[str, Any]:
    """
    Создать базу знаний QuickSight.
    CreateKnowledgeBase нет в текущем boto3 — используем прямой REST-запрос.
    """
    if not args.data_source_arn:
        return _friendly_error(
            "Не указан DataSourceArn.",
            "--data-source-arn обязателен для create-kb.",
        )

    # Получаем credentials из текущей сессии
    session = boto3.DEFAULT_SESSION or boto3.Session()
    creds = session.get_credentials()
    if creds is None:
        return _friendly_error(
            "Учётные данные AWS не найдены.",
            "Проверьте ~/.aws/credentials или AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY.",
        )
    frozen = creds.get_frozen_credentials()
    region = args.region or session.region_name
    if region is None:
        return _friendly_error(
            "Регион AWS не указан.",
            "Передайте --region или установите AWS_DEFAULT_REGION.",
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


def action_list_kbs(client: boto3.client, args: argparse.Namespace) -> dict:
    """Список всех баз знаний."""
    kwargs = {"AwsAccountId": args.aws_account_id}
    if args.max_results:
        kwargs["MaxResults"] = args.max_results
    if args.starting_token:
        kwargs["NextToken"] = args.starting_token

    return client.list_knowledge_bases(**kwargs)


def action_delete_kb(client: boto3.client, args: argparse.Namespace) -> dict:
    """Удалить базу знаний по ID."""
    return client.delete_knowledge_base(
        AwsAccountId=args.aws_account_id,
        KnowledgeBaseId=args.id,
    )


# ---------------------------------------------------------------------------
# Парсер аргументов
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="quicksight-kb-cli",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            CLI для управления QuickSight Knowledge Bases (июнь 2026).

            Зависимости: pip install boto3>=1.43.25
            Учётные данные: ~/.aws/credentials или AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
        """),
        epilog=textwrap.dedent("""\
            Примеры:
              # Создать базу знаний
              python3 quicksight-kb-cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 create-kb \\
                  --name "Support KB" --type SHAREPOINT \\
                  --data-source-arn arn:aws:quicksight:us-east-1:123456789012:datasource/xxx

              # Список всех баз знаний (с пагинацией)
              python3 quicksight-kb-cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 list-kbs --max-results 20

              # Удалить базу знаний
              python3 quicksight-kb-cli.py --region us-east-1 \\
                  --aws-account-id 123456789012 delete-kb --id kb-abc123
        """),
    )

    # Глобальные параметры
    parser.add_argument("--region", default=None, help="AWS-регион")
    parser.add_argument("--profile", default=None, help="Профиль из ~/.aws/credentials")
    parser.add_argument("--aws-account-id", required=True, help="12-значный AWS Account ID")
    parser.add_argument("--endpoint-url", default=None, help="Кастомный endpoint (отладка)")
    parser.add_argument("--debug", action="store_true", help="Debug-логирование boto3")

    # Сабпарсеры
    subparsers = parser.add_subparsers(dest="action", required=True, help="Доступные действия")

    # --- create-kb ---
    create_parser = subparsers.add_parser("create-kb", help="Создать базу знаний")
    create_parser.add_argument("--name", required=True, help="Название базы знаний")
    create_parser.add_argument(
        "--type", required=True,
        choices=["SHAREPOINT", "S3", "SALESFORCE", "SERVICENOW", "JIRA", "CONFLUENCE", "CUSTOM"],
        help="Тип источника данных",
    )
    create_parser.add_argument("--source-uri", default=None, help="URI источника (например, URL SharePoint)")
    create_parser.add_argument(
        "--data-source-arn", required=True,
        help="ARN источника данных QuickSight (arn:aws:quicksight:...:datasource/...)",
    )

    # --- list-kbs ---
    list_parser = subparsers.add_parser("list-kbs", help="Список баз знаний")
    list_parser.add_argument("--max-results", type=int, default=None, help="Макс. результатов")
    list_parser.add_argument("--starting-token", default=None, help="Токен пагинации")

    # --- delete-kb ---
    del_parser = subparsers.add_parser("delete-kb", help="Удалить базу знаний")
    del_parser.add_argument("--id", required=True, help="ID базы знаний (KnowledgeBaseId)")

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _setup_debug_logging() -> None:
    """Включает debug-логирование boto3 через современный API.

    ВНИМАНИЕ: debug-режим может вывести AWS credentials в stdout.
    Используйте только в изолированных средах.
    """
    logging.basicConfig(level=logging.DEBUG)
    for logger_name in ("boto3", "botocore", "s3transfer", "urllib3"):
        logging.getLogger(logger_name).setLevel(logging.DEBUG)
        logging.getLogger(logger_name).propagate = True


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Сессия boto3
    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region

    try:
        session = boto3.Session(**session_kwargs)
        # DEFAULT_SESSION нужен для action_create_kb, который берёт creds
        # из глобальной сессии для SigV4-подписи
        boto3.DEFAULT_SESSION = session
    except Exception as e:
        print(_friendly_error("Не удалось создать AWS-сессию.", str(e)), file=sys.stderr)
        return EXIT_FAILURE

    # Клиент quicksight
    client_kwargs: Dict[str, Any] = {
        "service_name": SERVICE_NAME,
        "config": BOTO_TIMEOUT_CONFIG,
    }
    if args.endpoint_url:
        client_kwargs["endpoint_url"] = args.endpoint_url
    if args.debug:
        import logging
        _setup_debug_logging()

    try:
        client = session.client(**client_kwargs)
    except Exception as e:
        print(_friendly_error("Не удалось создать boto3-клиент.", str(e)), file=sys.stderr)
        return EXIT_FAILURE

    # Диспетчер действий
    action_map: Dict[str, Any] = {
        "create-kb": action_create_kb,
        "list-kbs": action_list_kbs,
        "delete-kb": action_delete_kb,
    }

    handler = action_map.get(args.action)
    if handler is None:
        print(_friendly_error(f"Неизвестное действие: {args.action}"), file=sys.stderr)
        return EXIT_FAILURE

    try:
        result = handler(client, args)
        if isinstance(result, str):
            print(result, file=sys.stderr)
            return EXIT_FAILURE
    except Exception as e:
        print(_handle_boto3_error(e), file=sys.stderr)
        return EXIT_FAILURE

    preview = json.dumps(result, indent=2, ensure_ascii=False, default=str)
    if _is_empty_listing(result, args.action):
        print("[INFO] Ресурсы не найдены. API вернул пустой список.", file=sys.stderr)
    print(preview)
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())