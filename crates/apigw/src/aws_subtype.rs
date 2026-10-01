//! HTTP API integration subtypes: `AWS_PROXY` integrations that call an AWS
//! service API (`SQS-SendMessage`, `EventBridge-PutEvents`, ...) with
//! parameters mapped from the request, and answer with the service's response.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-aws-services-reference.html>

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderValue, Method, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value};

use crate::aws::RoleArn;
use crate::aws_service::{Protocol, Service, ServiceCall};
use crate::gateway::{ApiContext, GatewayError};
use crate::mapping::ServiceParameters;
use crate::pipeline::RequestContext;
use crate::proxy::UrlEncoder;

/// An integration subtype of an HTTP API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Subtype {
    SqsSendMessage,
    SqsReceiveMessage,
    SqsDeleteMessage,
    SqsPurgeQueue,
    EventBridgePutEvents,
    StepFunctionsStartExecution,
    StepFunctionsStartSyncExecution,
    StepFunctionsStopExecution,
    KinesisPutRecord,
    AppConfigGetConfiguration,
}

impl FromStr for Subtype {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "SQS-SendMessage" => Ok(Self::SqsSendMessage),
            "SQS-ReceiveMessage" => Ok(Self::SqsReceiveMessage),
            "SQS-DeleteMessage" => Ok(Self::SqsDeleteMessage),
            "SQS-PurgeQueue" => Ok(Self::SqsPurgeQueue),
            "EventBridge-PutEvents" => Ok(Self::EventBridgePutEvents),
            "StepFunctions-StartExecution" => Ok(Self::StepFunctionsStartExecution),
            "StepFunctions-StartSyncExecution" => Ok(Self::StepFunctionsStartSyncExecution),
            "StepFunctions-StopExecution" => Ok(Self::StepFunctionsStopExecution),
            "Kinesis-PutRecord" => Ok(Self::KinesisPutRecord),
            "AppConfig-GetConfiguration" => Ok(Self::AppConfigGetConfiguration),
            other => Err(format!(
                "the integration subtype {other:?} is not supported (supported: SQS-SendMessage, SQS-ReceiveMessage, SQS-DeleteMessage, SQS-PurgeQueue, EventBridge-PutEvents, StepFunctions-StartExecution, StepFunctions-StartSyncExecution, StepFunctions-StopExecution, Kinesis-PutRecord, AppConfig-GetConfiguration)"
            )),
        }
    }
}

impl Subtype {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::SqsSendMessage => "SQS-SendMessage",
            Self::SqsReceiveMessage => "SQS-ReceiveMessage",
            Self::SqsDeleteMessage => "SQS-DeleteMessage",
            Self::SqsPurgeQueue => "SQS-PurgeQueue",
            Self::EventBridgePutEvents => "EventBridge-PutEvents",
            Self::StepFunctionsStartExecution => "StepFunctions-StartExecution",
            Self::StepFunctionsStartSyncExecution => "StepFunctions-StartSyncExecution",
            Self::StepFunctionsStopExecution => "StepFunctions-StopExecution",
            Self::KinesisPutRecord => "Kinesis-PutRecord",
            Self::AppConfigGetConfiguration => "AppConfig-GetConfiguration",
        }
    }

    fn service(self) -> Service {
        match self {
            Self::SqsSendMessage
            | Self::SqsReceiveMessage
            | Self::SqsDeleteMessage
            | Self::SqsPurgeQueue => Service::SQS,
            Self::EventBridgePutEvents => Service::EVENTS,
            Self::StepFunctionsStartExecution
            | Self::StepFunctionsStartSyncExecution
            | Self::StepFunctionsStopExecution => Service::STATES,
            Self::KinesisPutRecord => Service::KINESIS,
            Self::AppConfigGetConfiguration => Service::APPCONFIG,
        }
    }

    /// The service API action this subtype calls.
    fn action(self) -> &'static str {
        match self {
            Self::SqsSendMessage => "SendMessage",
            Self::SqsReceiveMessage => "ReceiveMessage",
            Self::SqsDeleteMessage => "DeleteMessage",
            Self::SqsPurgeQueue => "PurgeQueue",
            Self::EventBridgePutEvents => "PutEvents",
            Self::StepFunctionsStartExecution => "StartExecution",
            Self::StepFunctionsStartSyncExecution => "StartSyncExecution",
            Self::StepFunctionsStopExecution => "StopExecution",
            Self::KinesisPutRecord => "PutRecord",
            Self::AppConfigGetConfiguration => "GetConfiguration",
        }
    }
}

/// The request parameters of a subtype call, by name.
struct Parameters<'a>(&'a BTreeMap<String, String>);

impl Parameters<'_> {
    fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    fn require(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("the required parameter {name} has no value"))
    }
}

/// A subtype call as the service takes it, before routing and signing.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Shaped {
    method: Method,
    path: String,
    query: Vec<(String, String)>,
    body: Bytes,
    content_type: Option<&'static str>,
}

impl Subtype {
    fn shape(self, params: &Parameters<'_>) -> Result<Shaped, String> {
        match self {
            Self::SqsSendMessage => {
                let mut form = Form::action("SendMessage");
                form.add("MessageBody", params.require("MessageBody")?);
                for name in ["DelaySeconds", "MessageDeduplicationId", "MessageGroupId"] {
                    form.add_optional(name, params.get(name));
                }
                form.add_attributes("MessageAttribute", params.get("MessageAttributes"))?;
                form.add_attributes(
                    "MessageSystemAttribute",
                    params.get("MessageSystemAttributes"),
                )?;
                Self::sqs(params, &form)
            }
            Self::SqsReceiveMessage => {
                let mut form = Form::action("ReceiveMessage");
                for name in [
                    "MaxNumberOfMessages",
                    "ReceiveRequestAttemptId",
                    "VisibilityTimeout",
                    "WaitTimeSeconds",
                ] {
                    form.add_optional(name, params.get(name));
                }
                form.add_list("AttributeName", params.get("AttributeNames"))?;
                form.add_list("MessageAttributeName", params.get("MessageAttributeNames"))?;
                Self::sqs(params, &form)
            }
            Self::SqsDeleteMessage => {
                let mut form = Form::action("DeleteMessage");
                form.add("ReceiptHandle", params.require("ReceiptHandle")?);
                Self::sqs(params, &form)
            }
            Self::SqsPurgeQueue => Self::sqs(params, &Form::action("PurgeQueue")),
            Self::EventBridgePutEvents => Self::put_events(params),
            Self::StepFunctionsStartExecution | Self::StepFunctionsStartSyncExecution => {
                let mut body = Map::new();
                Self::copy(
                    params,
                    &mut body,
                    &["StateMachineArn"],
                    &["Input", "Name", "TraceHeader"],
                )?;
                Ok(Self::json(&body))
            }
            Self::StepFunctionsStopExecution => {
                let mut body = Map::new();
                Self::copy(params, &mut body, &["ExecutionArn"], &["Cause", "Error"])?;
                Ok(Self::json(&body))
            }
            Self::KinesisPutRecord => Self::put_record(params),
            Self::AppConfigGetConfiguration => Self::get_configuration(params),
        }
    }

    /// An SQS query-protocol call to the queue's path.
    fn sqs(params: &Parameters<'_>, form: &Form) -> Result<Shaped, String> {
        let queue = reqwest::Url::parse(params.require("QueueUrl")?)
            .map_err(|err| format!("QueueUrl is not a URL: {err}"))?;
        Ok(Shaped {
            method: Method::POST,
            path: queue.path().to_owned(),
            query: Vec::new(),
            body: Bytes::from(form.encode()),
            content_type: Some("application/x-www-form-urlencoded"),
        })
    }

    fn json(body: &Map<String, Value>) -> Shaped {
        Shaped {
            method: Method::POST,
            path: "/".to_owned(),
            query: Vec::new(),
            body: Bytes::from(Value::Object(body.clone()).to_string()),
            content_type: None,
        }
    }

    /// Copies `required` (an error when absent) and `optional` parameters into
    /// a JSON body as strings.
    fn copy(
        params: &Parameters<'_>,
        body: &mut Map<String, Value>,
        required: &[&str],
        optional: &[&str],
    ) -> Result<(), String> {
        for name in required {
            body.insert(
                (*name).to_owned(),
                Value::String(params.require(name)?.to_owned()),
            );
        }
        for name in optional {
            if let Some(value) = params.get(name) {
                body.insert((*name).to_owned(), Value::String(value.to_owned()));
            }
        }
        Ok(())
    }

    fn put_events(params: &Parameters<'_>) -> Result<Shaped, String> {
        let mut entry = Map::new();
        Self::copy(
            params,
            &mut entry,
            &["Detail", "DetailType", "Source"],
            &["EventBusName", "Time", "TraceHeader"],
        )?;
        if let Some(resources) = params.get("Resources") {
            let resources: Value = serde_json::from_str(resources)
                .map_err(|err| format!("Resources is not a JSON array: {err}"))?;
            entry.insert("Resources".to_owned(), resources);
        }
        let mut body = Map::new();
        body.insert(
            "Entries".to_owned(),
            Value::Array(vec![Value::Object(entry)]),
        );
        Ok(Self::json(&body))
    }

    /// Kinesis takes the record's data base64-encoded.
    fn put_record(params: &Parameters<'_>) -> Result<Shaped, String> {
        let mut body = Map::new();
        Self::copy(
            params,
            &mut body,
            &["PartitionKey"],
            &[
                "StreamName",
                "StreamARN",
                "ExplicitHashKey",
                "SequenceNumberForOrdering",
            ],
        )?;
        if !body.contains_key("StreamName") && !body.contains_key("StreamARN") {
            return Err("StreamName or StreamARN is required".to_owned());
        }
        body.insert(
            "Data".to_owned(),
            Value::String(BASE64.encode(params.require("Data")?)),
        );
        Ok(Self::json(&body))
    }

    fn get_configuration(params: &Parameters<'_>) -> Result<Shaped, String> {
        let segment = |name: &str| -> Result<String, String> {
            let mut encoded = String::new();
            UrlEncoder(&mut encoded).component(params.require(name)?);
            Ok(encoded)
        };
        let mut query = vec![(
            "client_id".to_owned(),
            params.require("ClientId")?.to_owned(),
        )];
        if let Some(version) = params.get("ClientConfigurationVersion") {
            query.push((
                "client_configuration_version".to_owned(),
                version.to_owned(),
            ));
        }
        Ok(Shaped {
            method: Method::GET,
            path: format!(
                "/applications/{}/environments/{}/configurations/{}",
                segment("Application")?,
                segment("Environment")?,
                segment("Configuration")?
            ),
            query,
            body: Bytes::new(),
            content_type: None,
        })
    }
}

/// A query-protocol request body: `Action=...&Name=value`.
struct Form(Vec<(String, String)>);

impl Form {
    fn action(action: &str) -> Self {
        Self(vec![("Action".to_owned(), action.to_owned())])
    }

    fn add(&mut self, name: &str, value: &str) {
        self.0.push((name.to_owned(), value.to_owned()));
    }

    fn add_optional(&mut self, name: &str, value: Option<&str>) {
        if let Some(value) = value {
            self.add(name, value);
        }
    }

    /// `Name.1=a&Name.2=b` from a JSON array of strings.
    fn add_list(&mut self, name: &str, list: Option<&str>) -> Result<(), String> {
        let Some(list) = list else {
            return Ok(());
        };
        let items: Vec<String> = serde_json::from_str(list)
            .map_err(|err| format!("{name}s is not a JSON array of strings: {err}"))?;
        for (index, item) in items.iter().enumerate() {
            self.add(&format!("{name}.{}", index.saturating_add(1)), item);
        }
        Ok(())
    }

    /// `Name.1.Name=n&Name.1.Value.DataType=String&Name.1.Value.StringValue=v`
    /// from a JSON object of `{"DataType": ..., "StringValue": ...}` values.
    fn add_attributes(&mut self, prefix: &str, attributes: Option<&str>) -> Result<(), String> {
        let Some(attributes) = attributes else {
            return Ok(());
        };
        let attributes: BTreeMap<String, BTreeMap<String, String>> =
            serde_json::from_str(attributes).map_err(|err| {
                format!("{prefix}s is not a JSON object of attribute values: {err}")
            })?;
        for (index, (name, value)) in attributes.iter().enumerate() {
            let number = index.saturating_add(1);
            self.add(&format!("{prefix}.{number}.Name"), name);
            for (field, text) in value {
                self.add(&format!("{prefix}.{number}.Value.{field}"), text);
            }
        }
        Ok(())
    }

    fn encode(&self) -> String {
        let mut out = String::new();
        for (index, (name, value)) in self.0.iter().enumerate() {
            if index > 0 {
                out.push('&');
            }
            UrlEncoder(&mut out).component(name);
            out.push('=');
            UrlEncoder(&mut out).component(value);
        }
        out
    }
}

/// A compiled HTTP API integration subtype.
#[derive(Debug, Clone)]
pub(crate) struct SubtypeIntegration {
    pub(crate) subtype: Subtype,
    parameters: ServiceParameters,
    pub(crate) role: Option<RoleArn>,
    timeout: Duration,
}

impl SubtypeIntegration {
    pub(crate) fn new(
        subtype: Subtype,
        parameters: ServiceParameters,
        role: Option<RoleArn>,
        timeout: Duration,
    ) -> Self {
        Self {
            subtype,
            parameters,
            role,
            timeout,
        }
    }

    /// Calls the service with the mapped parameters and answers with its
    /// status, content type, and body.
    pub(crate) async fn call(
        &self,
        api: &ApiContext,
        ctx: &mut RequestContext,
    ) -> Result<Response, GatewayError> {
        let values = self.parameters.resolve(ctx);
        let shaped = self.subtype.shape(&Parameters(&values)).map_err(|reason| {
            tracing::error!(
                subtype = self.subtype.name(),
                reason,
                "invalid integration parameters"
            );
            GatewayError::ApiConfiguration
        })?;
        let region = Self::region(api, &values).ok_or_else(|| {
            tracing::error!(
                subtype = self.subtype.name(),
                "no Region parameter, and none is configured"
            );
            GatewayError::ApiConfiguration
        })?;
        let service = self.subtype.service();
        let mut headers = HeaderMap::new();
        if let Some(content_type) = shaped.content_type {
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
        }
        let json_service = matches!(service.protocol, Protocol::Json { .. });
        let call = ServiceCall {
            service,
            partition: "aws".to_owned(),
            region,
            method: shaped.method,
            path: shaped.path,
            query: shaped.query,
            headers,
            body: shaped.body,
            action: json_service.then(|| self.subtype.action().to_owned()),
        };
        let reply = call
            .execute(&api.aws, &api.http, self.role.as_ref(), self.timeout)
            .await
            .map_err(|error| {
                tracing::warn!(subtype = self.subtype.name(), %error, "AWS service call failed");
                GatewayError::from(&error)
            })?;
        ctx.integration.status = Some(reply.status);
        let mut response = Response::new(Body::from(reply.body));
        *response.status_mut() = axum::http::StatusCode::from_u16(reply.status)
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        if let Some(content_type) = reply.headers.get(header::CONTENT_TYPE) {
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, content_type.clone());
        }
        Ok(response)
    }

    /// The `Region` parameter; else the region in an SQS queue URL's host; else
    /// the gateway's own region.
    fn region(api: &ApiContext, values: &BTreeMap<String, String>) -> Option<String> {
        values
            .get("Region")
            .cloned()
            .or_else(|| {
                let queue = reqwest::Url::parse(values.get("QueueUrl")?).ok()?;
                let host = queue.host_str()?;
                host.strip_prefix("sqs.")?
                    .split('.')
                    .next()
                    .map(str::to_owned)
            })
            .or_else(|| api.aws.default_region())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn shape(subtype: Subtype, params: &[(&str, &str)]) -> Result<Shaped, String> {
        let map: BTreeMap<String, String> = params
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        subtype.shape(&Parameters(&map))
    }

    #[test]
    fn subtype_names_round_trip() {
        for name in [
            "SQS-SendMessage",
            "SQS-ReceiveMessage",
            "SQS-DeleteMessage",
            "SQS-PurgeQueue",
            "EventBridge-PutEvents",
            "StepFunctions-StartExecution",
            "StepFunctions-StartSyncExecution",
            "StepFunctions-StopExecution",
            "Kinesis-PutRecord",
            "AppConfig-GetConfiguration",
        ] {
            assert_eq!(name.parse::<Subtype>().unwrap().name(), name);
        }
        assert!(
            "SQS-Unknown"
                .parse::<Subtype>()
                .unwrap_err()
                .contains("not supported")
        );
    }

    #[test]
    fn send_message_is_a_form_post_to_the_queue_path() {
        let shaped = shape(
            Subtype::SqsSendMessage,
            &[
                (
                    "QueueUrl",
                    "https://sqs.eu-west-1.amazonaws.com/123456789012/orders",
                ),
                ("MessageBody", "hello world"),
                ("DelaySeconds", "5"),
                (
                    "MessageAttributes",
                    r#"{"kind":{"DataType":"String","StringValue":"order"}}"#,
                ),
            ],
        )
        .unwrap();
        assert_eq!(shaped.path, "/123456789012/orders");
        assert_eq!(shaped.method, Method::POST);
        assert_eq!(
            String::from_utf8(shaped.body.to_vec()).unwrap(),
            "Action=SendMessage&MessageBody=hello%20world&DelaySeconds=5\
             &MessageAttribute.1.Name=kind&MessageAttribute.1.Value.DataType=String\
             &MessageAttribute.1.Value.StringValue=order"
        );
        assert_eq!(
            shaped.content_type,
            Some("application/x-www-form-urlencoded")
        );
    }

    #[test]
    fn receive_message_numbers_list_parameters() {
        let shaped = shape(
            Subtype::SqsReceiveMessage,
            &[
                ("QueueUrl", "https://sqs.us-east-1.amazonaws.com/1/q"),
                ("AttributeNames", r#"["All","SentTimestamp"]"#),
                ("MaxNumberOfMessages", "3"),
            ],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(shaped.body.to_vec()).unwrap(),
            "Action=ReceiveMessage&MaxNumberOfMessages=3&AttributeName.1=All&AttributeName.2=SentTimestamp"
        );
    }

    #[test]
    fn delete_and_purge_need_their_parameters() {
        let queue = ("QueueUrl", "https://sqs.us-east-1.amazonaws.com/1/q");
        assert!(
            shape(Subtype::SqsDeleteMessage, &[queue])
                .unwrap_err()
                .contains("ReceiptHandle")
        );
        let delete = shape(Subtype::SqsDeleteMessage, &[queue, ("ReceiptHandle", "h=")]).unwrap();
        assert_eq!(
            String::from_utf8(delete.body.to_vec()).unwrap(),
            "Action=DeleteMessage&ReceiptHandle=h%3D"
        );
        let purge = shape(Subtype::SqsPurgeQueue, &[queue]).unwrap();
        assert_eq!(
            String::from_utf8(purge.body.to_vec()).unwrap(),
            "Action=PurgeQueue"
        );
        assert!(
            shape(Subtype::SqsPurgeQueue, &[])
                .unwrap_err()
                .contains("QueueUrl")
        );
        assert!(
            shape(Subtype::SqsPurgeQueue, &[("QueueUrl", "not a url")])
                .unwrap_err()
                .contains("not a URL")
        );
    }

    #[test]
    fn put_events_wraps_one_entry() {
        let shaped = shape(
            Subtype::EventBridgePutEvents,
            &[
                ("Detail", r#"{"a":1}"#),
                ("DetailType", "order.created"),
                ("Source", "shop"),
                ("Resources", r#"["arn:aws:x"]"#),
                ("EventBusName", "bus"),
            ],
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&shaped.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"Entries": [{
                "Detail": "{\"a\":1}", "DetailType": "order.created", "Source": "shop",
                "Resources": ["arn:aws:x"], "EventBusName": "bus"
            }]})
        );
        assert!(
            shape(
                Subtype::EventBridgePutEvents,
                &[
                    ("Source", "s"),
                    ("DetailType", "t"),
                    ("Detail", "{}"),
                    ("Resources", "nope")
                ]
            )
            .unwrap_err()
            .contains("Resources")
        );
    }

    #[test]
    fn put_record_base64_encodes_the_data() {
        let shaped = shape(
            Subtype::KinesisPutRecord,
            &[
                ("StreamName", "s"),
                ("PartitionKey", "k"),
                ("Data", "hello"),
            ],
        )
        .unwrap();
        let body: Value = serde_json::from_slice(&shaped.body).unwrap();
        assert_eq!(
            body,
            serde_json::json!({"StreamName": "s", "PartitionKey": "k", "Data": "aGVsbG8="})
        );
        assert!(
            shape(
                Subtype::KinesisPutRecord,
                &[("PartitionKey", "k"), ("Data", "x")]
            )
            .unwrap_err()
            .contains("StreamName")
        );
    }

    #[test]
    fn step_functions_pass_their_fields_through() {
        let start = shape(
            Subtype::StepFunctionsStartExecution,
            &[
                ("StateMachineArn", "arn:aws:states:::sm"),
                ("Input", "{}"),
                ("Name", "run-1"),
            ],
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&start.body).unwrap(),
            serde_json::json!({"StateMachineArn": "arn:aws:states:::sm", "Input": "{}", "Name": "run-1"})
        );
        let stop = shape(
            Subtype::StepFunctionsStopExecution,
            &[("ExecutionArn", "arn:aws:states:::exec"), ("Cause", "why")],
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&stop.body).unwrap(),
            serde_json::json!({"ExecutionArn": "arn:aws:states:::exec", "Cause": "why"})
        );
        assert!(shape(Subtype::StepFunctionsStartSyncExecution, &[]).is_err());
    }

    #[test]
    fn app_config_is_a_get_with_the_client_id_in_the_query() {
        let shaped = shape(
            Subtype::AppConfigGetConfiguration,
            &[
                ("Application", "app one"),
                ("Environment", "prod"),
                ("Configuration", "flags"),
                ("ClientId", "c1"),
                ("ClientConfigurationVersion", "7"),
            ],
        )
        .unwrap();
        assert_eq!(shaped.method, Method::GET);
        assert_eq!(
            shaped.path,
            "/applications/app%20one/environments/prod/configurations/flags"
        );
        assert_eq!(
            shaped.query,
            [
                ("client_id".to_owned(), "c1".to_owned()),
                ("client_configuration_version".to_owned(), "7".to_owned())
            ]
        );
        assert!(shaped.body.is_empty());
    }
}
