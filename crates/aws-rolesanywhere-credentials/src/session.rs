//! The `CreateSession` request body and response.

use std::time::SystemTime;

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};

/// The name credentials from this crate report as their provider.
pub(crate) const PROVIDER_NAME: &str = "RolesAnywhere";

/// Why `CreateSession` produced no credentials.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// Roles Anywhere answered with an error status.
    #[error("CreateSession answered {status}: {message}")]
    Status {
        /// The HTTP status code.
        status: u16,
        /// The error's `message`, or the body when it has none.
        message: String,
    },
    /// The response body is not a `CreateSession` response.
    #[error("CreateSession answered with an unreadable body: {0}")]
    Malformed(#[source] serde_json::Error),
    /// The response holds no credentials.
    #[error("CreateSession answered without credentials")]
    NoCredentials,
    /// The credentials' expiration is not a timestamp.
    #[error("CreateSession answered with an unreadable expiration {0:?}")]
    Expiration(String),
}

/// The JSON body of `CreateSession`. The certificate travels in the `X-Amz-X509` header and
/// the ARNs in the query string, as the AWS credential helper sends them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateSessionBody {
    pub(crate) duration_seconds: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSessionResponse {
    #[serde(default)]
    credential_set: Vec<CredentialSet>,
}

#[derive(Deserialize)]
struct CredentialSet {
    credentials: Option<SessionCredentials>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SessionCredentials {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(alias = "Message")]
    message: Option<String>,
}

/// The credentials in a `CreateSession` response with `status` and `body`.
pub(crate) fn parse_response(status: u16, body: &[u8]) -> Result<Credentials, SessionError> {
    if !(200..300).contains(&status) {
        let message = serde_json::from_slice::<ErrorBody>(body)
            .ok()
            .and_then(|error| error.message)
            .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
        return Err(SessionError::Status { status, message });
    }
    let response: CreateSessionResponse =
        serde_json::from_slice(body).map_err(SessionError::Malformed)?;
    let Some(credentials) = response
        .credential_set
        .into_iter()
        .next()
        .and_then(|set| set.credentials)
    else {
        return Err(SessionError::NoCredentials);
    };
    let Some(expiry) = credentials
        .expiration
        .parse::<jiff::Timestamp>()
        .ok()
        .and_then(|expiry| SystemTime::try_from(expiry).ok())
    else {
        return Err(SessionError::Expiration(credentials.expiration));
    };
    Ok(Credentials::new(
        credentials.access_key_id,
        credentials.secret_access_key,
        Some(credentials.session_token),
        Some(expiry),
        PROVIDER_NAME,
    ))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    const RESPONSE: &str = r#"{
        "credentialSet": [{
            "assumedRoleUser": {"arn": "arn:aws:sts::1:assumed-role/r/s", "assumedRoleId": "A:s"},
            "credentials": {
                "accessKeyId": "ASIAEXAMPLE",
                "secretAccessKey": "secret",
                "sessionToken": "token",
                "expiration": "2026-11-23T13:00:00Z"
            },
            "packedPolicySize": 0,
            "roleArn": "arn:aws:iam::1:role/r",
            "sourceIdentity": "CN=client"
        }],
        "subjectArn": "arn:aws:rolesanywhere:us-east-1:1:subject/x"
    }"#;

    #[test]
    fn the_first_credential_set_becomes_expiring_credentials() {
        let credentials = parse_response(201, RESPONSE.as_bytes()).unwrap();
        assert_eq!(credentials.access_key_id(), "ASIAEXAMPLE");
        assert_eq!(credentials.secret_access_key(), "secret");
        assert_eq!(credentials.session_token(), Some("token"));
        let expected: jiff::Timestamp = "2026-11-23T13:00:00Z".parse().unwrap();
        assert_eq!(
            credentials.expiry(),
            Some(SystemTime::try_from(expected).unwrap())
        );
    }

    #[test]
    fn the_request_body_carries_only_the_session_duration() {
        let body = serde_json::to_string(&CreateSessionBody {
            duration_seconds: 3600,
        })
        .unwrap();
        assert_eq!(body, r#"{"durationSeconds":3600}"#);
    }

    #[test]
    fn error_statuses_report_the_service_message_or_the_body() {
        let error = parse_response(403, br#"{"message":"Untrusted certificate."}"#).unwrap_err();
        assert_eq!(
            error.to_string(),
            "CreateSession answered 403: Untrusted certificate."
        );
        let error = parse_response(400, br#"{"Message":"bad"}"#).unwrap_err();
        assert_eq!(error.to_string(), "CreateSession answered 400: bad");
        let error = parse_response(502, b"bad gateway").unwrap_err();
        assert_eq!(error.to_string(), "CreateSession answered 502: bad gateway");
        assert!(matches!(
            parse_response(199, b""),
            Err(SessionError::Status { status: 199, .. })
        ));
        assert!(matches!(
            parse_response(300, b""),
            Err(SessionError::Status { status: 300, .. })
        ));
    }

    #[test]
    fn unusable_bodies_are_errors() {
        assert!(matches!(
            parse_response(200, b"not json"),
            Err(SessionError::Malformed(_))
        ));
        assert!(matches!(
            parse_response(200, br#"{"credentialSet": []}"#),
            Err(SessionError::NoCredentials)
        ));
        assert!(matches!(
            parse_response(200, b"{}"),
            Err(SessionError::NoCredentials)
        ));
        assert!(matches!(
            parse_response(200, br#"{"credentialSet": [{}]}"#),
            Err(SessionError::NoCredentials)
        ));
        let late = RESPONSE.replace("2026-11-23T13:00:00Z", "tomorrow");
        let error = parse_response(200, late.as_bytes()).unwrap_err();
        assert_eq!(
            error.to_string(),
            "CreateSession answered with an unreadable expiration \"tomorrow\""
        );
    }
}
