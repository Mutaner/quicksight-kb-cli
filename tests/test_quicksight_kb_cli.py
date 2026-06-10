"""Tests for quicksight-kb-cli."""

import argparse
import hashlib
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, "..")

from quicksight_kb_cli import (
    EXIT_FAILURE,
    _friendly_error,
    _is_empty_listing,
    _rest_call,
    _setup_debug_logging,
    _sigv4_sign,
    build_parser,
    cmd_list_kbs,
    cmd_delete_kb,
    main,
)


# ---------------------------------------------------------------------------
# _friendly_error
# ---------------------------------------------------------------------------

class TestFriendlyError:
    def test_with_msg_only(self):
        r = _friendly_error("Critical failure.")
        assert r == "[ERROR] Critical failure."

    def test_with_msg_and_detail(self):
        r = _friendly_error("Failed.", "Check logs.")
        assert r == "[ERROR] Failed.\nCheck logs."

    def test_empty_detail(self):
        r = _friendly_error("Error", "")
        assert r == "[ERROR] Error"


# ---------------------------------------------------------------------------
# _is_empty_listing
# ---------------------------------------------------------------------------

class TestIsEmptyListing:
    def test_empty_kb_summaries_returns_true(self):
        assert _is_empty_listing({"KnowledgeBaseSummaries": []}, "list-kbs") is True

    def test_non_empty_returns_false(self):
        assert _is_empty_listing(
            {"KnowledgeBaseSummaries": [{"KnowledgeBaseId": "1"}]}, "list-kbs"
        ) is False

    def test_wrong_action_returns_false(self):
        assert _is_empty_listing({"KnowledgeBaseSummaries": []}, "create-kb") is False

    def test_not_a_dict_returns_false(self):
        assert _is_empty_listing("not a dict", "list-kbs") is False

    def test_missing_key_returns_false(self):
        assert _is_empty_listing({}, "list-kbs") is False

    def test_summaries_is_none_returns_false(self):
        assert _is_empty_listing({"KnowledgeBaseSummaries": None}, "list-kbs") is False

    def test_irrelevant_keys_ignored(self):
        """Only KnowledgeBaseSummaries is checked."""
        assert _is_empty_listing({"Flows": [], "Ids": []}, "list-kbs") is False


# ---------------------------------------------------------------------------
# _sigv4_sign
# ---------------------------------------------------------------------------

class TestSigV4Sign:
    def test_headers_contain_required_keys(self):
        headers = _sigv4_sign(
            method="GET",
            host="quicksight.us-east-1.amazonaws.com",
            path="/v1/accounts/123/knowledge-bases/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtuFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token="",
        )
        assert "Authorization" in headers
        assert "x-amz-date" in headers
        assert "x-amz-content-sha256" in headers
        assert "Content-Type" in headers
        assert headers["Content-Type"] == "application/json"

    def test_x_amz_date_iso8601(self):
        headers = _sigv4_sign(
            method="GET",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtuFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token="",
        )
        date_val = headers["x-amz-date"]
        assert len(date_val) == 16
        assert date_val[8] == "T"
        assert date_val.endswith("Z")

    def test_session_token_included(self):
        headers = _sigv4_sign(
            method="POST",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="test",
            session_token="IQoJb3JpZ2luX2VjEXAMPLE",
        )
        assert "x-amz-security-token" in headers
        assert headers["x-amz-security-token"] == "IQoJb3JpZ2luX2VjEXAMPLE"

    def test_authorization_contains_credential(self):
        headers = _sigv4_sign(
            method="GET",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="wJalrXUtuFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            session_token="",
        )
        auth = headers["Authorization"]
        assert "Credential=AKIDEXAMPLE" in auth
        assert "SignedHeaders=" in auth
        assert "Signature=" in auth

    def test_no_secret_key_in_headers(self):
        secret = "super-secret-key-do-not-expose"
        headers = _sigv4_sign(
            method="GET",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key=secret,
            session_token="",
        )
        header_str = str(headers)
        assert secret not in header_str

    def test_query_params_encoded(self):
        headers = _sigv4_sign(
            method="GET",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="test",
            session_token="",
            query_params={"max-results": "10", "next-token": "abc"},
        )
        assert "Authorization" in headers

    def test_x_amz_content_sha256_matches_body(self):
        body = b'{"Name":"Test"}'
        headers = _sigv4_sign(
            method="POST",
            host="quicksight.us-east-1.amazonaws.com",
            path="/",
            region="us-east-1",
            service="quicksight",
            access_key="AKIDEXAMPLE",
            secret_key="test",
            session_token="",
            body=body,
        )
        expected = hashlib.sha256(body).hexdigest()
        assert headers["x-amz-content-sha256"] == expected


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------

class TestBuildParser:
    def test_parser_created(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_help_exits_ok(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["--help"])
        assert exc.value.code == 0

    def test_missing_aws_account_id_raises_system_exit(self):
        parser = build_parser()
        with pytest.raises(SystemExit) as exc:
            parser.parse_args(["list-kbs"])
        assert exc.value.code == 2

    def test_list_kbs_minimal_args(self):
        parser = build_parser()
        args = parser.parse_args(["--aws-account-id", "123456789012", "list-kbs"])
        assert args.action == "list-kbs"
        assert args.aws_account_id == "123456789012"

    def test_create_kb_minimal_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--aws-account-id", "123456789012",
            "create-kb",
            "--name", "Test",
            "--type", "S3",
            "--data-source-arn", "arn:aws:quicksight:us-east-1:1:datasource/ds-1",
        ])
        assert args.action == "create-kb"
        assert args.name == "Test"

    def test_delete_kb_minimal_args(self):
        parser = build_parser()
        args = parser.parse_args([
            "--aws-account-id", "123456789012",
            "delete-kb",
            "--id", "kb-abc123",
        ])
        assert args.action == "delete-kb"
        assert args.id == "kb-abc123"

    def test_invalid_type_raises_system_exit(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([
                "--aws-account-id", "123456789012",
                "create-kb",
                "--name", "Test",
                "--type", "INVALID",
                "--data-source-arn", "arn:aws:quicksight:...",
            ])

    def test_non_int_max_results_raises_system_exit(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([
                "--aws-account-id", "123456789012",
                "list-kbs",
                "--max-results", "abc",
            ])

    def test_debug_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--debug", "--aws-account-id", "123456789012", "list-kbs"])
        assert args.debug is True


# ---------------------------------------------------------------------------
# cmd_list_kbs
# ---------------------------------------------------------------------------

class TestCmdListKbs:
    def test_minimal(self):
        client = MagicMock()
        client.list_knowledge_bases.return_value = {"KnowledgeBaseSummaries": []}
        args = argparse.Namespace(aws_account_id="123456789012", max_results=None, starting_token=None)
        result = cmd_list_kbs(client, args)
        assert result == {"KnowledgeBaseSummaries": []}

    def test_with_pagination(self):
        client = MagicMock()
        args = argparse.Namespace(aws_account_id="123", max_results=5, starting_token="tok")
        cmd_list_kbs(client, args)
        kwargs = client.list_knowledge_bases.call_args[1]
        assert kwargs["MaxResults"] == 5
        assert kwargs["NextToken"] == "tok"


# ---------------------------------------------------------------------------
# cmd_delete_kb
# ---------------------------------------------------------------------------

class TestCmdDeleteKb:
    def test_delete_called_with_correct_params(self):
        client = MagicMock()
        client.delete_knowledge_base.return_value = {"Status": 200}
        args = argparse.Namespace(aws_account_id="123", id="kb-xxx")
        result = cmd_delete_kb(client, args)
        kwargs = client.delete_knowledge_base.call_args[1]
        assert kwargs["AwsAccountId"] == "123"
        assert kwargs["KnowledgeBaseId"] == "kb-xxx"
        assert result == {"Status": 200}


# ---------------------------------------------------------------------------
# _setup_debug_logging
# ---------------------------------------------------------------------------

class TestSetupDebugLogging:
    def test_runs_without_exception(self):
        _setup_debug_logging()

    def test_warning_printed_to_stderr(self, capsys):
        _setup_debug_logging()
        captured = capsys.readouterr()
        assert "WARNING" in captured.err


# ---------------------------------------------------------------------------
# _rest_call
# ---------------------------------------------------------------------------

class TestRestCall:
    def test_http_error_raises_runtime_error(self):
        """When urllib raises HTTPError, _rest_call wraps it in RuntimeError."""
        with patch("urllib.request.urlopen") as mock_urlopen:
            from urllib.error import HTTPError
            from io import BytesIO

            # Simulate a 403 error response
            mock_urlopen.side_effect = HTTPError(
                url="https://example.com",
                code=403,
                msg="Forbidden",
                hdrs={},
                fp=BytesIO(b'{"message":"Access denied"}'),
            )
            with pytest.raises(RuntimeError) as exc:
                _rest_call(
                    method="GET",
                    path="/test",
                    region="us-east-1",
                    access_key="AKIDEXAMPLE",
                    secret_key="test",
                    session_token="",
                )
            assert "HTTP 403" in str(exc.value)

    def test_network_error_raises_runtime_error(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            from urllib.error import URLError
            mock_urlopen.side_effect = URLError(reason="Connection refused")

            with pytest.raises(RuntimeError) as exc:
                _rest_call(
                    method="GET",
                    path="/test",
                    region="us-east-1",
                    access_key="AKIDEXAMPLE",
                    secret_key="test",
                    session_token="",
                )
            assert "Network error" in str(exc.value)


# ---------------------------------------------------------------------------
# main() integration smoke test
# ---------------------------------------------------------------------------

class TestMain:
    def test_no_args_exits_failure(self):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0