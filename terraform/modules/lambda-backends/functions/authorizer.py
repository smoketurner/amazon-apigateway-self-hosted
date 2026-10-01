"""Deterministic Lambda authorizer for the parity reference stack.

The decision depends only on the credential value: "allow" authorizes, "deny"
returns a Deny policy (or isAuthorized=false), anything else raises, which API
Gateway reports as 401 Unauthorized. The credential is the authorizationToken of
a TOKEN authorizer, or the x-auth header of a REQUEST authorizer.
"""

CREDENTIAL_HEADER = "x-auth"
PRINCIPAL = "parity-user"


def _credential(event):
    if event.get("type") == "TOKEN":
        return event.get("authorizationToken")
    headers = {name.lower(): value for name, value in (event.get("headers") or {}).items()}
    return headers.get(CREDENTIAL_HEADER)


def _policy(effect, method_arn, context):
    # method_arn is arn:aws:execute-api:<region>:<account>:<api>/<stage>/<method>/<path>;
    # widening to the whole stage keeps cached policies valid for every method.
    api_arn, stage = method_arn.split("/")[:2]
    return {
        "principalId": PRINCIPAL,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": f"{api_arn}/{stage}/*/*",
                }
            ],
        },
        "context": context,
    }


def handler(event, context):
    credential = _credential(event)
    claims = {"principal": PRINCIPAL, "credential": str(credential)}

    if event.get("version") == "2.0":
        return {"isAuthorized": credential == "allow", "context": claims}

    if credential == "allow":
        return _policy("Allow", event["methodArn"], claims)
    if credential == "deny":
        return _policy("Deny", event["methodArn"], claims)
    raise Exception("Unauthorized")
