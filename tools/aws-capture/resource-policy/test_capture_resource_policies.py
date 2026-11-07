"""Offline tests for capture_resource_policies. Run with: pytest tools/aws-capture/resource-policy -q"""

import json
import re

import pytest

import capture_resource_policies as capture

DEBUG_LOG = """\
2026-11-07 09:48:02,700 - MainThread - urllib3.connectionpool - DEBUG - https://s3.eu-north-1.amazonaws.com:443 "PUT /floci-policy-capture-0a1b2c3d4e5f?policy HTTP/1.1" 400 None
2026-11-07 09:48:02,910 - MainThread - botocore.parsers - DEBUG - Response body:
b'<?xml version="1.0" encoding="UTF-8"?>\\n<Error><Code>MalformedPolicy</Code><Message>Invalid Condition type : </Message><RequestId>R</RequestId></Error>'
2026-11-07 09:48:02,912 - MainThread - botocore.hooks - DEBUG - Event needs-retry.s3.PutBucketPolicy
"""


@pytest.fixture(params=sorted(capture.TARGETS))
def target(request):
    return capture.TARGETS[request.param]


def test_case_ids_are_unique_and_kebab_case(target):
    ids = [case["id"] for case in capture.cases(target)]
    assert len(ids) == len(set(ids))
    assert all(re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", case_id) for case_id in ids)


def test_cases_name_only_placeholders(target):
    for case in capture.cases(target):
        accounts = set(re.findall(r"\d{12}", case["policy"]))
        assert accounts <= {capture.ACCOUNT}, case["id"]


def test_well_formed_cases_deny_only_the_target_action(target):
    # A denial of anything else could lock the capture out of its own scratch resource.
    for case in capture.cases(target):
        try:
            document = json.loads(case["policy"])
        except ValueError:
            continue
        statements = document.get("Statement") if isinstance(document, dict) else None
        for statement in statements if isinstance(statements, list) else [statements]:
            if isinstance(statement, dict) and str(statement.get("Effect", "")).lower() == "deny":
                assert statement.get("Action") == target.action, case["id"]
                assert "NotAction" not in statement, case["id"]


def test_reads_status_and_untrimmed_message_from_the_debug_log():
    body = capture.ast.literal_eval(capture.BODY.findall(DEBUG_LOG)[-1]).decode("utf-8")
    assert capture.STATUS.findall(DEBUG_LOG) == ["400"]
    assert capture.S3.error(body) == ("MalformedPolicy", "Invalid Condition type : ")


def test_swap_restores_placeholders():
    live = "floci-policy-capture-0a1b2c3d4e5f"
    outward = {capture.ACCOUNT: "999988887777", "floci-policy-capture": live}
    inward = {"999988887777": capture.ACCOUNT, live: "floci-policy-capture"}
    text = f"arn:aws:s3:::floci-policy-capture/* {capture.ROOT}"
    assert capture.swap(capture.swap(text, outward), inward) == text


def test_failure_without_a_response_prints_no_debug_output(monkeypatch):
    # botocore logs the canonical request across several untimestamped lines, token included.
    stderr = (
        "2026-11-07 09:48:02,700 - MainThread - botocore.auth - DEBUG - CanonicalRequest:\n"
        "PUT\n/\npolicy=\nhost:s3.eu-north-1.amazonaws.com\n"
        "x-amz-security-token:FlociSecretSessionToken\n"
        "\nUnable to locate credentials. FlociSecretSessionToken\n"
    )

    def run(*args, **kwargs):
        return capture.subprocess.CompletedProcess(args[0], 253, "", stderr)

    monkeypatch.setattr(capture.subprocess, "run", run)
    aws = capture.Aws("profile", "eu-north-1", "https://s3.eu-north-1.amazonaws.com")
    with pytest.raises(RuntimeError) as raised:
        aws.call("s3api", "put-bucket-policy", {"Bucket": "b", "Policy": "{}"}, capture.S3.error)
    assert "FlociSecretSessionToken" not in str(raised.value)
    assert "x-amz-security-token" not in str(raised.value)
    assert "253" in str(raised.value)
