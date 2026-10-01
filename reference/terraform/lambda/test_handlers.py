"""Offline checks for the reference Lambdas: python3 -m unittest discover reference/terraform/lambda"""

import importlib
import json
import os
import unittest

import authorizer
import echo

V2_EVENT = {
    "version": "2.0",
    "rawPath": "/x",
    "requestContext": {"http": {"method": "GET"}},
    "headers": {"X-Echo-Secret": "s3cret", "x-keep": "1"},
    "queryStringParameters": {},
}
METHOD_ARN = "arn:aws:execute-api:us-east-1:123456789012:abc/ref/GET/authz/token"


class EchoTests(unittest.TestCase):
    def test_proxy_event_is_echoed_with_secret_redacted(self):
        response = echo.handler(V2_EVENT, None)
        self.assertEqual(response["statusCode"], 200)
        body = json.loads(response["body"])
        self.assertEqual(body["headers"]["X-Echo-Secret"], "[redacted]")
        self.assertEqual(body["headers"]["x-keep"], "1")

    def test_non_proxy_event_is_returned_as_is(self):
        self.assertEqual(echo.handler({"a": 1}, None), {"a": 1})

    def test_non_proxy_failure_raises_error_message(self):
        with self.assertRaisesRegex(Exception, "^Error: forced failure$"):
            echo.handler({"body": {"fail": True}}, None)

    def test_status_and_binary_overrides(self):
        teapot = {**V2_EVENT, "queryStringParameters": {"echo_status": "418"}}
        self.assertEqual(echo.handler(teapot, None)["statusCode"], 418)
        binary = {**V2_EVENT, "queryStringParameters": {"echo_binary": "1"}}
        response = echo.handler(binary, None)
        self.assertTrue(response["isBase64Encoded"])
        self.assertEqual(response["headers"]["content-type"], "image/png")

    def test_shared_secret_is_enforced_when_configured(self):
        os.environ["ECHO_SHARED_SECRET"] = "s3cret"
        try:
            guarded = importlib.reload(echo)
            self.assertEqual(guarded.handler(V2_EVENT, None)["statusCode"], 200)
            wrong = {**V2_EVENT, "headers": {"x-echo-secret": "nope"}}
            self.assertEqual(guarded.handler(wrong, None)["statusCode"], 403)
            self.assertEqual(guarded.handler({**V2_EVENT, "headers": {}}, None)["statusCode"], 403)
        finally:
            del os.environ["ECHO_SHARED_SECRET"]
            importlib.reload(echo)


class AuthorizerTests(unittest.TestCase):
    def test_token_allow_deny_and_unauthorized(self):
        allow = authorizer.handler(
            {"type": "TOKEN", "authorizationToken": "allow", "methodArn": METHOD_ARN}, None
        )
        statement = allow["policyDocument"]["Statement"][0]
        self.assertEqual(statement["Effect"], "Allow")
        self.assertEqual(statement["Resource"], "arn:aws:execute-api:us-east-1:123456789012:abc/ref/*/*")
        deny = authorizer.handler(
            {"type": "TOKEN", "authorizationToken": "deny", "methodArn": METHOD_ARN}, None
        )
        self.assertEqual(deny["policyDocument"]["Statement"][0]["Effect"], "Deny")
        with self.assertRaisesRegex(Exception, "^Unauthorized$"):
            authorizer.handler(
                {"type": "TOKEN", "authorizationToken": "other", "methodArn": METHOD_ARN}, None
            )

    def test_request_authorizer_reads_header_case_insensitively(self):
        event = {"type": "REQUEST", "headers": {"X-Auth": "allow"}, "methodArn": METHOD_ARN}
        self.assertEqual(
            authorizer.handler(event, None)["policyDocument"]["Statement"][0]["Effect"], "Allow"
        )

    def test_http_api_simple_response(self):
        self.assertTrue(authorizer.handler({"version": "2.0", "headers": {"x-auth": "allow"}}, None)["isAuthorized"])
        self.assertFalse(authorizer.handler({"version": "2.0", "headers": {}}, None)["isAuthorized"])


if __name__ == "__main__":
    unittest.main()
