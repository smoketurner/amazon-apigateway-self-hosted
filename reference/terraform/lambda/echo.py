"""Echo backend for the parity reference stack.

Proxy-shaped events (API Gateway REST/HTTP API, Lambda function URL) are answered
with a proxy-format response whose body is the received event as JSON. Any other
event is a non-proxy invocation, and the event itself is returned.

Query parameters steer the response so one function covers many cases:
  echo_status=<int>        status code of a proxy response
  echo_binary=1            respond with fixed binary bytes (base64 encoded)
  echo_content_type=<mime> content type of the binary response (default image/png)

When ECHO_SHARED_SECRET is set (the function URL deployment), requests must carry
a matching x-echo-secret header, and the header is redacted in the echoed event.
"""

import base64
import json
import os

SECRET = os.environ.get("ECHO_SHARED_SECRET")
SECRET_HEADER = "x-echo-secret"
BINARY_BODY = bytes(range(256))


def _is_proxy_event(event):
    return (
        isinstance(event, dict)
        and "requestContext" in event
        and ("httpMethod" in event or event.get("version") == "2.0")
    )


def _response(status, body, content_type="application/json", encoded=False):
    return {
        "statusCode": status,
        "headers": {"content-type": content_type},
        "body": body,
        "isBase64Encoded": encoded,
    }


def _redact_secret(event):
    headers = event.get("headers")
    if not isinstance(headers, dict):
        return event
    redacted = {
        name: "[redacted]" if name.lower() == SECRET_HEADER else value
        for name, value in headers.items()
    }
    return {**event, "headers": redacted}


def handler(event, context):
    if not _is_proxy_event(event):
        if isinstance(event, dict) and (event.get("body") or {}).get("fail"):
            raise Exception("Error: forced failure")
        return event

    headers = {name.lower(): value for name, value in (event.get("headers") or {}).items()}
    if SECRET is not None and headers.get(SECRET_HEADER) != SECRET:
        return _response(403, json.dumps({"message": "forbidden"}))

    query = event.get("queryStringParameters") or {}
    if query.get("echo_binary") == "1":
        return _response(
            200,
            base64.b64encode(BINARY_BODY).decode("ascii"),
            content_type=query.get("echo_content_type", "image/png"),
            encoded=True,
        )

    status = int(query.get("echo_status", "200"))
    return _response(status, json.dumps(_redact_secret(event), sort_keys=True))
