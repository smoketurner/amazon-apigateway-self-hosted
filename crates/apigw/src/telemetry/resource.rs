//! The OpenTelemetry resource: who emits the telemetry.
//!
//! Built in increasing precedence from: `service.name=apigw` and the binary's
//! `service.version`; Kubernetes attributes from downward API environment
//! variables ([`KUBERNETES`]); `OTEL_RESOURCE_ATTRIBUTES`; and
//! `OTEL_SERVICE_NAME`, which always names the service when set.

use std::collections::BTreeMap;

use opentelemetry::KeyValue;
use opentelemetry_sdk::Resource;

/// Environment variables the Helm chart fills from the downward API, and the
/// resource attribute each becomes.
pub(crate) const KUBERNETES: [(&str, &str); 6] = [
    ("K8S_POD_NAME", "k8s.pod.name"),
    ("K8S_POD_UID", "k8s.pod.uid"),
    ("K8S_NAMESPACE_NAME", "k8s.namespace.name"),
    ("K8S_NODE_NAME", "k8s.node.name"),
    ("K8S_CONTAINER_NAME", "k8s.container.name"),
    ("K8S_DEPLOYMENT_NAME", "k8s.deployment.name"),
];

/// Resource attributes, by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Attributes(BTreeMap<String, String>);

impl Attributes {
    pub(crate) fn from_env(env: impl Fn(&str) -> Option<String>) -> Self {
        let mut attributes = BTreeMap::new();
        attributes.insert("service.name".to_owned(), "apigw".to_owned());
        attributes.insert(
            "service.version".to_owned(),
            env!("CARGO_PKG_VERSION").to_owned(),
        );
        for (variable, attribute) in KUBERNETES {
            if let Some(value) = env(variable).filter(|v| !v.is_empty()) {
                attributes.insert(attribute.to_owned(), value);
            }
        }
        if let Some(uid) = attributes.get("k8s.pod.uid").cloned() {
            attributes.insert("service.instance.id".to_owned(), uid);
        }
        if let Some(listed) = env("OTEL_RESOURCE_ATTRIBUTES") {
            attributes.extend(Self::parse_list(&listed));
        }
        if let Some(name) = env("OTEL_SERVICE_NAME").filter(|v| !v.is_empty()) {
            attributes.insert("service.name".to_owned(), name);
        }
        Self(attributes)
    }

    /// `key1=value1,key2=value2`, values percent-encoded (W3C Baggage octets).
    /// Malformed entries are skipped.
    fn parse_list(listed: &str) -> Vec<(String, String)> {
        listed
            .split(',')
            .filter_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                let key = key.trim();
                if key.is_empty() {
                    return None;
                }
                Some((key.to_owned(), Self::percent_decoded(value.trim())?))
            })
            .collect()
    }

    fn percent_decoded(value: &str) -> Option<String> {
        let mut bytes = Vec::with_capacity(value.len());
        let mut rest = value.as_bytes();
        while let Some((&byte, tail)) = rest.split_first() {
            if byte == b'%' {
                let (hex, tail) = tail.split_at_checked(2)?;
                let hex = std::str::from_utf8(hex).ok()?;
                bytes.push(u8::from_str_radix(hex, 16).ok()?);
                rest = tail;
            } else {
                bytes.push(byte);
                rest = tail;
            }
        }
        String::from_utf8(bytes).ok()
    }

    pub(crate) fn resource(&self) -> Resource {
        Resource::builder_empty()
            .with_attributes(
                self.0
                    .iter()
                    .map(|(key, value)| KeyValue::new(key.clone(), value.clone())),
            )
            .build()
    }

    #[cfg(test)]
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn attributes(vars: &[(&str, &str)]) -> Attributes {
        let vars: HashMap<&str, &str> = vars.iter().copied().collect();
        Attributes::from_env(|name| vars.get(name).map(|v| (*v).to_owned()))
    }

    #[test]
    fn the_service_is_apigw_at_this_version_by_default() {
        let attrs = attributes(&[]);
        assert_eq!(attrs.get("service.name"), Some("apigw"));
        assert_eq!(
            attrs.get("service.version"),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(attrs.get("k8s.pod.name"), None);
    }

    #[test]
    fn downward_api_variables_become_kubernetes_attributes() {
        let attrs = attributes(&[
            ("K8S_POD_NAME", "apigw-7d9"),
            ("K8S_POD_UID", "0b6c"),
            ("K8S_NAMESPACE_NAME", "edge"),
            ("K8S_NODE_NAME", "node-1"),
            ("K8S_CONTAINER_NAME", "apigw"),
            ("K8S_DEPLOYMENT_NAME", "apigw"),
            ("K8S_NODE_IP", "ignored"),
        ]);
        assert_eq!(attrs.get("k8s.pod.name"), Some("apigw-7d9"));
        assert_eq!(attrs.get("k8s.pod.uid"), Some("0b6c"));
        assert_eq!(attrs.get("service.instance.id"), Some("0b6c"));
        assert_eq!(attrs.get("k8s.namespace.name"), Some("edge"));
        assert_eq!(attrs.get("k8s.node.name"), Some("node-1"));
        assert_eq!(attrs.get("k8s.container.name"), Some("apigw"));
        assert_eq!(attrs.get("k8s.deployment.name"), Some("apigw"));
        assert_eq!(attrs.0.len(), 9);
    }

    #[test]
    fn resource_attributes_override_detected_ones_and_the_service_name_wins() {
        let attrs = attributes(&[
            ("K8S_NAMESPACE_NAME", "edge"),
            (
                "OTEL_RESOURCE_ATTRIBUTES",
                "k8s.namespace.name=prod, deployment.environment.name=prod%20eu,service.name=from-list,=x,bad,pct=%zz",
            ),
        ]);
        assert_eq!(attrs.get("k8s.namespace.name"), Some("prod"));
        assert_eq!(attrs.get("deployment.environment.name"), Some("prod eu"));
        assert_eq!(attrs.get("service.name"), Some("from-list"));
        assert_eq!(attrs.get("pct"), None, "malformed escapes are skipped");
        let named = attributes(&[
            ("OTEL_RESOURCE_ATTRIBUTES", "service.name=from-list"),
            ("OTEL_SERVICE_NAME", "edge-gateway"),
        ]);
        assert_eq!(named.get("service.name"), Some("edge-gateway"));
    }

    #[test]
    fn the_resource_carries_every_attribute() {
        let resource = attributes(&[("K8S_POD_NAME", "p")]).resource();
        assert_eq!(
            resource
                .get(&opentelemetry::Key::from_static_str("k8s.pod.name"))
                .map(|v| v.to_string()),
            Some("p".to_owned())
        );
    }
}
