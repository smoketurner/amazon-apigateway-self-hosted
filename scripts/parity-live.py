"""Sends the same AWS-service requests to the deployed reference APIs and to apigw on ECS.

Replay has no stand-in for AWS services, so these integrations are compared live: each request
goes to API Gateway and to the ECS gateway (REST on 8443, HTTP on 8444), which call the same
resources with the same integration role. Values that differ per request (IDs, sequence
numbers, times) are masked, then status, content type, and body must match.

usage: parity-live.py OUTPUTS_JSON GATEWAY_IP
"""

import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

MASKS = [
    (re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"), "<uuid>"),
    (re.compile(r"Root=1-[0-9a-f]{8}-[0-9a-f]{24}"), "Root=<trace>"),
    (re.compile(r"\b\d{10,}(\.\d+)?\b"), "<number>"),
    (re.compile(r"\d{4}-\d{2}-\d{2}T[\d:.]+Z?"), "<time>"),
    (re.compile(r"(<RequestId>)[^<]+"), r"\1<id>"),
    (re.compile(r'("x-amz-request-id"|"RequestId")\s*:\s*"[^"]*"'), r'\1:"<id>"'),
]


def mask(text):
    """Replace the values that differ per request with placeholders."""
    for pattern, replacement in MASKS:
        text = pattern.sub(replacement, text)
    return text


def send(url, method, body, insecure):
    """Send one request and return its status, content type, and body."""
    context = ssl.create_default_context()
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    data = body.encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        request.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(request, context=context, timeout=30) as response:
            return response.status, response.headers.get("content-type"), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.headers.get("content-type"), error.read().decode()


def cases(run):
    """List the requests as (api, label, method, path, body), with keys unique to `run`."""
    obj = f"live-{run}.txt"
    rest = [
        ("sqs", "POST", "/aws/sqs", '{"m":1}'),
        ("dynamodb-put", "POST", "/aws/dynamodb", json.dumps({"id": f"live-{run}", "v": 1})),
        ("dynamodb-get", "GET", f"/aws/dynamodb/live-{run}", None),
        ("dynamodb-get-missing", "GET", f"/aws/dynamodb/absent-{run}", None),
        ("stepfunctions", "POST", "/aws/stepfunctions", '{"n":2}'),
        ("eventbridge", "POST", "/aws/eventbridge", '{"e":3}'),
        ("sns", "POST", "/aws/sns", '{"s":4}'),
        ("kinesis", "POST", "/aws/kinesis", '{"k":5}'),
        ("s3-put", "PUT", f"/aws/s3/{obj}", "object body"),
        ("s3-get", "GET", f"/aws/s3/{obj}", None),
        ("s3-get-missing", "GET", f"/aws/s3/absent-{run}.txt", None),
        ("lambda-nonproxy", "POST", "/lambda-nonproxy", '{"x":1}'),
        ("lambda-nonproxy-error", "POST", "/lambda-nonproxy", '{"fail":true}'),
    ]
    http = [
        ("subtype-sqs", "POST", "/subtype/sqs", '{"m":1}'),
        ("subtype-eventbridge", "POST", "/subtype/eventbridge", '{"e":3}'),
        ("subtype-stepfunctions", "POST", "/subtype/stepfunctions", '{"n":2}'),
        ("subtype-kinesis", "POST", "/subtype/kinesis", '{"k":5}'),
    ]
    return [("rest", *case) for case in rest] + [("http", *case) for case in http]


def main():
    """Compare every case and exit non-zero when any differs."""
    with open(sys.argv[1]) as file:
        outputs = json.load(file)
    gateway_ip = sys.argv[2]
    stage = outputs["stage"]
    bases = {
        "rest": (outputs["rest"]["base_url"].rstrip("/"), f"https://{gateway_ip}:8443/{stage}"),
        "http": (outputs["http"]["base_url"].rstrip("/"), f"https://{gateway_ip}:8444/{stage}"),
    }
    run = str(int(time.time()))
    differ = 0
    for api, label, method, path, body in cases(run):
        aws_base, gateway_base = bases[api]
        expected = send(aws_base + path, method, body, insecure=False)
        actual = send(gateway_base + path, method, body, insecure=True)
        same = describe(expected, limit=None) == describe(actual, limit=None)
        differ += not same
        print(f"{'PASS' if same else 'DIFF'} {api:4} {label:22} {expected[0]} {expected[1]}")
        if not same:
            print(f"       aws:   {describe(expected)}")
            print(f"       apigw: {describe(actual)}")
    print(f"{differ} of {len(cases(run))} differ")
    sys.exit(1 if differ else 0)


def describe(answer, limit=300):
    """Render an answer as one masked line, cut to `limit` characters of body."""
    status, content_type, body = answer
    return f"{status} {content_type} {mask(body)[:limit]}"


if __name__ == "__main__":
    main()
