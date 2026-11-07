"""Opt-in AWS oracle capture for S3 bucket-policy validation.

Sends a corpus of synthetic resource policies to S3 PutBucketPolicy and records, for each policy,
whether S3 accepted it or the HTTP status, error code and message it returned. Normal tests replay
the recorded fixture without credentials or network access. The S3 class below holds what is
specific to S3: how to create, put to and delete one scratch bucket, the action, resource and
condition key the cases use, and how to read an error from the response body.

Most cases break the IAM policy grammar once; the order-* cases break it twice, to pin which
violation S3 reports first; the service-* cases are valid grammar that only S3's own checks reject.

The capture creates one scratch bucket, sends every case to it, and deletes it. Policies use
placeholder identifiers that are swapped for the live ones on the way out and back on the way
in, so the fixture holds neither the caller's account id nor the scratch bucket's name.

    python3 tools/aws-capture/resource-policy/capture_resource_policies.py --service s3 \\
        --profile <profile> --region eu-west-1 --endpoint-url https://s3.eu-west-1.amazonaws.com \\
        --output src/test/resources/resource-policy/s3-put-bucket-policy-aws.json
"""

import argparse
import ast
import datetime
import json
from pathlib import Path
import re
import secrets
import subprocess
import time
from xml.etree import ElementTree

# Stands in for the caller's account in every fixture.
ACCOUNT = "111122223333"
ROOT = f"arn:aws:iam::{ACCOUNT}:root"
# A principal of the caller's account that the capture never creates.
MISSING_ROLE = f"arn:aws:iam::{ACCOUNT}:role/floci-capture-missing-role"
THROTTLED = {"SlowDown", "Throttling", "ThrottlingException", "RequestLimitExceeded"}
# The CLI trims the message it prints, and AWS may end one in a space, so the capture reads the
# response itself from botocore's debug log: the body as a bytes literal and urllib3's status line.
BODY = re.compile(r"botocore\.parsers - DEBUG - Response body:\n(b'.*'|b\".*\")$", re.MULTILINE)
STATUS = re.compile(r'HTTP/1\.1" (\d{3}) ')


class S3:
    """PutBucketPolicy on a scratch bucket. S3 requires every statement to name a resource."""

    name = "s3"
    operation = "PutBucketPolicy"
    reference = "https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html"
    placeholder = "floci-policy-capture"
    action = "s3:GetObject"
    resource = f"arn:aws:s3:::{placeholder}/*"
    foreign_action = "sqs:SendMessage"
    foreign_resource = f"arn:aws:sqs:us-east-1:{ACCOUNT}:floci-capture-queue"
    condition_key = "s3:FlociUndefinedKey"
    # Any other code means the capture itself went wrong (credentials, a public policy, a gone bucket).
    error_codes = {"MalformedPolicy"}

    @staticmethod
    def endpoint(region):
        return f"https://s3.{region}.amazonaws.com"

    def create(self, aws):
        bucket = f"{self.placeholder}-{secrets.token_hex(6)}"
        request = {"Bucket": bucket}
        if aws.region != "us-east-1":
            request["CreateBucketConfiguration"] = {"LocationConstraint": aws.region}
        aws.check("s3api", "create-bucket", request, self.error)
        return bucket

    def put(self, aws, bucket, policy):
        return aws.call("s3api", "put-bucket-policy", {"Bucket": bucket, "Policy": policy}, self.error)

    @staticmethod
    def error(body):
        root = ElementTree.fromstring(body)
        return root.findtext("Code"), root.findtext("Message")

    def delete(self, aws, bucket):
        aws.check("s3api", "delete-bucket-policy", {"Bucket": bucket}, self.error)
        aws.check("s3api", "delete-bucket", {"Bucket": bucket}, self.error)


TARGETS = {target.name: target for target in (S3(),)}


def cases(target):
    """The corpus, written with placeholder identifiers. Ids are stable: fixtures and gap lists key on them."""
    effect = '"Effect":"Allow"'
    principal = f'"Principal":{{"AWS":"{ROOT}"}}'
    not_principal = f'"NotPrincipal":{{"AWS":"{ROOT}"}}'
    action = f'"Action":"{target.action}"'
    resource = f'"Resource":"{target.resource}"'
    prefix, name = target.action.split(":")

    def statement(*members):
        return "{" + ",".join(members) + "}"

    def policy(*statements):
        return '{"Version":"2012-10-17","Statement":[' + ",".join(statements) + "]}"

    def document(*members):
        return "{" + ",".join(members) + "}"

    ok = statement(effect, principal, action, resource)
    statements = '"Statement":[' + ok + "]"
    version = '"Version":"2012-10-17"'

    def allow(member, *rest):
        return policy(statement(effect, principal, member, resource, *rest))

    def granting(member):
        return policy(statement(effect, member, action, resource))

    def denying(member):
        # Only ever deny the target's own harmless action, so a denial cannot lock the capture out.
        return policy(statement('"Effect":"Deny"', member, action, resource))

    def on(member):
        return policy(statement(effect, principal, action, member))

    def condition(value):
        return policy(statement(effect, principal, action, resource, '"Condition":' + value))

    result = []

    def add(case_id, text):
        result.append({"id": case_id, "policy": text})

    add("json-not-json", "not json")
    add("json-array", "[1]")
    add("json-leading-whitespace", " " + policy(ok))
    add("json-broken", "{bad")
    add("json-trailing-content", policy(ok) + " x")
    add("json-trailing-whitespace", policy(ok) + "\n")
    add("json-pretty-printed", json.dumps(json.loads(policy(ok)), indent=2))

    add("document-no-version", document(statements))
    add("document-2008-version", document('"Version":"2008-10-17"', statements))
    add("document-unknown-element", document(version, '"Foo":1', statements))
    add("document-lowercase-element", document('"version":"2012-10-17"', statements))
    add("document-bad-version", document('"Version":"2013-01-01"', statements))
    add("document-numeric-version", document('"Version":2012', statements))
    add("document-numeric-id", document(version, '"Id":1', statements))
    add("document-empty", "{}")
    add("document-no-statement", document(version))
    add("document-repeated-element", document(version, version, statements))
    add("document-version-last", document(statements, version))

    add("statement-single-object", document(version, '"Statement":' + ok))
    add("statement-empty-list", document(version, '"Statement":[]'))
    add("statement-string", document(version, '"Statement":"x"'))
    add("statement-null", document(version, '"Statement":null'))
    add("statement-not-object", document(version, '"Statement":[1]'))
    add("statement-empty-object", policy("{}"))
    add("statement-unknown-element", policy(statement(effect, principal, action, resource, '"Foo":1')))
    add("statement-lowercase-element", policy(statement('"effect":"Allow"', principal, action, resource)))
    add("statement-repeated-element", policy(statement(effect, principal, action, resource, '"Effect":"Deny"')))

    add("sid-numeric", policy(statement('"Sid":1', effect, principal, action, resource)))
    add("sid-empty", policy(statement('"Sid":""', effect, principal, action, resource)))
    add("sid-punctuation", policy(statement('"Sid":"a b-c!"', effect, principal, action, resource)))
    add("sid-repeated", policy(statement('"Sid":"A"', effect, principal, action, resource),
                               statement('"Sid":"A"', effect, principal, action, resource)))

    add("effect-missing", policy(statement(principal, action, resource)))
    add("effect-empty", policy(statement('"Effect":""', principal, action, resource)))
    add("effect-unknown", policy(statement('"Effect":"Permit"', principal, action, resource)))
    add("effect-numeric", policy(statement('"Effect":1', principal, action, resource)))
    add("effect-lowercase-allow", policy(statement('"Effect":"allow"', principal, action, resource)))
    add("effect-lowercase-deny", policy(statement('"Effect":"deny"', principal, action, resource)))

    add("principal-missing", policy(statement(effect, action, resource)))
    add("principal-and-not-principal", policy(statement(effect, principal, action, resource, not_principal)))
    add("principal-string", granting('"Principal":"me"'))
    add("principal-unknown-type", granting('"Principal":{"Foo":"x"}'))
    add("principal-empty-object", granting('"Principal":{}'))
    add("principal-empty-list", granting('"Principal":{"AWS":[]}'))
    add("principal-aws-name", granting('"Principal":{"AWS":"bob"}'))
    add("principal-empty-service", granting('"Principal":{"Service":""}'))
    add("principal-account", granting(f'"Principal":{{"AWS":"{ACCOUNT}"}}'))
    add("principal-federated", granting('"Principal":{"Federated":"cognito-identity.amazonaws.com"}'))
    add("principal-wildcard", denying('"Principal":"*"'))
    add("principal-aws-wildcard", denying('"Principal":{"AWS":"*"}'))
    add("principal-not-principal", denying(not_principal))
    add("principal-repeated-type", granting(f'"Principal":{{"AWS":"{ROOT}","AWS":"{ROOT}"}}'))

    add("action-missing", policy(statement(effect, principal, resource)))
    add("action-and-not-action", allow(action, action.replace('"Action"', '"NotAction"')))
    add("action-not-action", allow(action.replace('"Action"', '"NotAction"')))
    add("action-without-service", policy(statement(effect, principal, f'"Action":"{name}"', resource)))
    add("action-without-name", policy(statement(effect, principal, f'"Action":"{prefix}:"', resource)))
    add("action-with-space", policy(statement(effect, principal, f'"Action":"{prefix}:Get Object"', resource)))
    add("action-empty-list", policy(statement(effect, principal, '"Action":[]', resource)))
    add("action-numeric", policy(statement(effect, principal, '"Action":1', resource)))
    add("action-wildcard-service-and-name", policy(statement(effect, principal, '"Action":"*:*"', resource)))
    add("action-wildcard-name", policy(statement(effect, principal, f'"Action":"{prefix}:*"', resource)))

    add("resource-missing", policy(statement(effect, principal, action)))
    add("resource-and-not-resource",
        policy(statement(effect, principal, action, resource, resource.replace('"Resource"', '"NotResource"'))))
    add("resource-not-resource", on(resource.replace('"Resource"', '"NotResource"')))
    add("resource-not-arn", on('"Resource":"mybucket"'))
    add("resource-partial-arn", on(f'"Resource":"arn:aws:{prefix}"'))
    add("resource-empty-list", on('"Resource":[]'))
    add("resource-numeric", on('"Resource":1'))

    add("condition-unknown-operator", condition('{"StringEqualz":{"aws:SourceIp":"1.2.3.4"}}'))
    add("condition-null-if-exists", condition('{"NullIfExists":{"aws:UserAgent":"true"}}'))
    add("condition-unnamed-operator", condition('{"":{"aws:UserAgent":"a"}}'))
    add("condition-not-object", condition('"x"'))
    add("condition-nested-value", condition('{"StringEquals":{"aws:UserAgent":{"a":1}}}'))
    add("condition-null-value", condition('{"StringEquals":{"aws:UserAgent":null}}'))
    add("condition-blank-key", condition('{"StringEquals":{"":"a"}}'))
    add("condition-repeated-key", condition('{"StringEquals":{"aws:UserAgent":"a","aws:UserAgent":"b"}}'))
    add("condition-repeated-operator",
        condition('{"Bool":{"aws:SecureTransport":"true"},"Bool":{"aws:SecureTransport":"false"}}'))
    add("condition-boolean-value", condition('{"Bool":{"aws:SecureTransport":false}}'))
    add("condition-empty-values", condition('{"StringEquals":{"aws:UserAgent":[]}}'))
    add("condition-operator-without-keys", condition('{"StringEquals":{}}'))
    add("condition-set-operator", condition('{"ForAnyValue:StringLike":{"aws:UserAgent":"a"}}'))

    # Two violations each, named in document order: which one AWS reports is the point of the case.
    bad_action = f'"Action":"{name}"'
    bad_resource = '"Resource":"mybucket"'
    bad_principal = '"Principal":{"AWS":"bob"}'
    bad_effect = '"Effect":"Permit"'
    bad_condition = '"Condition":{"StringEqualz":{"aws:UserAgent":"a"}}'
    bad_statements = '"Statement":[' + statement(bad_effect, principal, action, resource) + "]"
    add("order-unknown-then-repeated", document('"Foo":1', version, version, statements))
    add("order-repeated-then-unknown", document(version, version, '"Foo":1', statements))
    add("order-bad-version-then-unknown", document('"Version":"2013-01-01"', '"Foo":1', statements))
    add("order-bad-version-then-no-statement", document('"Version":"2013-01-01"'))
    add("order-bad-statement-then-unknown", document(version, bad_statements, '"Foo":1'))
    add("order-bad-statement-then-bad-version", document(bad_statements, '"Version":"2013-01-01"'))
    add("order-unknown-then-broken-json", '{"Version":"2012-10-17","Foo":1,' + "bad")
    add("order-unknown-then-trailing-content", document(version, '"Foo":1', statements) + " x")
    add("order-bad-effect-then-unknown", policy(statement(bad_effect, '"Foo":1', principal, action, resource)))
    add("order-numeric-sid-then-unknown", policy(statement('"Sid":1', '"Foo":1', effect, principal, action, resource)))
    add("order-bad-effect-then-repeated", policy(statement(bad_effect, principal, action, resource, effect)))
    add("order-no-effect-or-principal", policy(statement(action, resource)))
    add("order-no-principal-or-action", policy(statement(effect, resource)))
    add("order-no-action-or-resource", policy(statement(effect, principal)))
    add("order-numeric-action-then-no-effect", policy(statement(principal, '"Action":1', resource)))
    add("order-bad-action-then-no-effect", policy(statement(principal, bad_action, resource)))
    add("order-bad-principal-then-no-effect", policy(statement(bad_principal, action, resource)))
    add("order-bad-resource-then-no-action", policy(statement(effect, principal, bad_resource)))
    add("order-empty-resource-then-no-action", policy(statement(effect, principal, '"Resource":[]')))
    add("order-bad-action-then-bad-resource", policy(statement(effect, principal, bad_action, bad_resource)))
    add("order-bad-resource-then-bad-action", policy(statement(effect, principal, bad_resource, bad_action)))
    add("order-bad-principal-then-bad-action", policy(statement(effect, bad_principal, bad_action, resource)))
    add("order-bad-action-then-bad-principal", policy(statement(effect, bad_action, bad_principal, resource)))
    add("order-bad-condition-then-bad-action", policy(statement(effect, principal, bad_condition, bad_action, resource)))
    add("order-bad-action-then-bad-condition", policy(statement(effect, principal, bad_action, resource, bad_condition)))
    add("order-not-principal-then-principal", policy(statement(effect, not_principal, principal, action, resource)))
    add("order-not-action-then-action",
        policy(statement(effect, principal, action.replace('"Action"', '"NotAction"'), action, resource)))
    add("order-bad-action-then-next-statement-no-effect",
        policy(statement(effect, principal, bad_action, resource), statement(principal, action, resource)))
    add("order-first-statement-first",
        policy(statement(effect, principal, resource), statement(effect, action, resource)))
    add("order-unknown-then-bad-version", document('"Foo":1', '"Version":"2013-01-01"', statements))
    add("order-numeric-id-then-unknown", document(version, '"Id":1', '"Foo":1', statements))
    add("order-repeated-then-bad-version", document(version, '"Version":"2013-01-01"', statements))
    add("order-statement-string-then-unknown", document(version, '"Statement":"x"', '"Foo":1'))
    add("order-statement-unknown-then-document-unknown",
        document(version, '"Statement":[' + statement(effect, principal, action, resource, '"Foo":1') + "]", '"Bar":1'))
    add("order-bad-statement-then-trailing-content", document(version, bad_statements) + " x")
    add("order-repeated-then-trailing-content", document(version, version, statements) + " x")
    add("order-no-statement-then-trailing-content", document(version) + " x")
    add("order-bad-effect-then-no-principal", policy(statement(bad_effect, action, resource)))
    add("order-repeated-then-no-effect", policy(statement(principal, action, resource, principal)))
    add("order-repeated-then-no-action", policy(statement(effect, principal, resource, effect)))
    add("order-conflict-then-no-action", policy(statement(effect, principal, not_principal, resource)))
    add("order-numeric-sid-then-no-effect", policy(statement('"Sid":1', principal, action, resource)))
    add("order-numeric-action-then-no-resource", policy(statement(effect, principal, '"Action":1')))
    add("order-empty-action-then-no-effect", policy(statement(principal, '"Action":[]', resource)))
    add("order-empty-resource-then-bad-action", policy(statement(effect, principal, bad_action, '"Resource":[]')))
    add("order-bad-condition-then-no-effect", policy(statement(principal, action, resource, bad_condition)))
    add("order-repeated-condition-key-then-no-effect", policy(statement(
        principal, action, resource, '"Condition":{"StringEquals":{"aws:UserAgent":"a","aws:UserAgent":"b"}}')))
    add("order-bad-condition-then-next-statement-no-effect",
        policy(statement(effect, principal, action, resource, bad_condition), statement(principal, action, resource)))
    add("order-numeric-action-then-next-statement-no-effect",
        policy(statement(effect, principal, '"Action":1', resource), statement(principal, action, resource)))
    add("order-bad-principal-then-next-statement-no-effect",
        policy(statement(effect, bad_principal, action, resource), statement(principal, action, resource)))

    add("service-foreign-action", policy(statement(effect, principal, f'"Action":"{target.foreign_action}"', resource)))
    add("service-undefined-action",
        policy(statement(effect, principal, f'"Action":"{prefix}:FlociUndefinedAction"', resource)))
    add("service-foreign-resource", on(f'"Resource":"{target.foreign_resource}"'))
    add("service-missing-principal", granting(f'"Principal":{{"AWS":"{MISSING_ROLE}"}}'))
    add("service-undefined-condition-key", condition(f'{{"StringEquals":{{"{target.condition_key}":"a"}}}}'))
    add("service-undefined-global-condition-key", condition('{"StringEquals":{"aws:FlociUndefinedKey":"a"}}'))
    return result


class Aws:
    def __init__(self, profile, region, endpoint):
        self.profile = profile
        self.region = region
        self.endpoint = endpoint

    def call(self, service, command, request, parse_error):
        """
        Runs one CLI command, retrying throttling. Returns None on success, else the error AWS
        returned as {status, code, message}; `parse_error` reads code and message from the body.
        The debug log holds request signatures and the session token, and not every line of it
        carries a timestamp, so no part of stderr is ever printed: when it holds no AWS response,
        the error names only the command and the CLI's exit code.
        """
        for attempt in range(5):
            completed = subprocess.run(
                ["aws", "--profile", self.profile, "--region", self.region,
                 "--endpoint-url", self.endpoint, "--no-cli-pager", "--output", "json", "--debug",
                 service, command, "--cli-input-json", json.dumps(request)],
                capture_output=True, text=True)
            if completed.returncode == 0:
                return None
            bodies = BODY.findall(completed.stderr)
            statuses = STATUS.findall(completed.stderr)
            if not bodies or not statuses:
                raise RuntimeError(f"{service} {command}: no AWS response (aws exited with {completed.returncode}); "
                                   "rerun the command without --debug to see why")
            code, message = parse_error(ast.literal_eval(bodies[-1]).decode("utf-8"))
            if code not in THROTTLED:
                return {"status": int(statuses[-1]), "code": code, "message": message}
            time.sleep(2 ** attempt)
        raise RuntimeError(f"{service} {command}: still throttled")

    def check(self, service, command, request, parse_error):
        error = self.call(service, command, request, parse_error)
        if error:
            raise RuntimeError(f"{service} {command} failed: {error['code']}: {error['message']}")

    def account(self):
        completed = subprocess.run(
            ["aws", "--profile", self.profile, "--region", self.region,
             "--endpoint-url", f"https://sts.{self.region}.amazonaws.com", "--no-cli-pager",
             "sts", "get-caller-identity", "--query", "Account", "--output", "text"],
            capture_output=True, text=True, check=True)
        return completed.stdout.strip()


def swap(text, replacements):
    """Replaces each key of `replacements` by its value, longest key first."""
    for old in sorted(replacements, key=len, reverse=True):
        text = text.replace(old, replacements[old])
    return text


def capture(target, aws):
    account = aws.account()
    resource = target.create(aws)
    outward = {ACCOUNT: account, target.placeholder: resource}
    inward = {account: ACCOUNT, resource: target.placeholder}
    recorded = []
    try:
        for case in cases(target):
            error = target.put(aws, resource, swap(case["policy"], outward))
            if error is None:
                recorded.append({**case, "accepted": True})
            elif error["code"] in target.error_codes:
                recorded.append({**case, "error": {**error, "message": swap(error["message"], inward)}})
            else:
                raise RuntimeError(f"{case['id']}: unexpected {error['code']}: {error['message']}")
            print(case["id"], json.dumps(recorded[-1].get("error", {}).get("message", "accepted")), flush=True)
            time.sleep(0.15)
    finally:
        target.delete(aws, resource)
    return recorded


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service", choices=sorted(TARGETS), required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--endpoint-url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    target = TARGETS[args.service]
    if args.endpoint_url != target.endpoint(args.region):
        parser.error("capture requires the explicit regional endpoint " + target.endpoint(args.region))
    cli = subprocess.run(["aws", "--version"], capture_output=True, text=True, check=True).stdout.split()[0]
    recorded = capture(target, Aws(args.profile, args.region, args.endpoint_url))
    fixture = {
        "provenance": {
            "verification": "Verified on Live AWS",
            "source": f"capture_resource_policies.py --service {target.name}",
            "operation": target.operation,
            "capturedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            "region": args.region,
            "endpoint": args.endpoint_url,
            "cli": cli,
            "inputs": "Synthetic policies only, sent to one scratch resource that the capture created and deleted.",
            "normalization": f"The caller's account id reads {ACCOUNT} and the scratch resource "
                             f"{target.placeholder}, in policies and messages alike.",
            "reference": target.reference,
        },
        "cases": recorded,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(fixture, indent=2) + "\n")


if __name__ == "__main__":
    main()
