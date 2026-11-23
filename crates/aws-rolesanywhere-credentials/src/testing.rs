//! Certificates, keys, and files for tests.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::{HttpRequest, HttpResponse};
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_types::body::SdkBody;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SerialNumber, SignatureAlgorithm,
};
use x509_parser::der_parser::der::parse_der;

/// A directory under the system temporary directory, removed when dropped.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "aws-rolesanywhere-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    pub(crate) fn write(&self, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
        let path = self.path(name);
        std::fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.0));
    }
}

/// An end-entity certificate issued through one intermediate.
pub(crate) struct Pki {
    pub(crate) leaf_pem: String,
    pub(crate) leaf_der: Vec<u8>,
    pub(crate) intermediate_pem: String,
    pub(crate) intermediate_der: Vec<u8>,
    pub(crate) key: KeyPair,
}

/// The serial number every test certificate carries.
pub(crate) const SERIAL: [u8; 16] = [
    0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

impl Pki {
    /// Issues a leaf with a key for `algorithm`.
    pub(crate) fn issue(algorithm: &'static SignatureAlgorithm) -> Self {
        Self::issue_with(KeyPair::generate_for(algorithm).unwrap())
    }

    pub(crate) fn issue_with(key: KeyPair) -> Self {
        let mut root_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = Issuer::new(root_params, KeyPair::generate().unwrap());

        let mut intermediate_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let intermediate_key = KeyPair::generate().unwrap();
        let intermediate = intermediate_params
            .signed_by(&intermediate_key, &root)
            .unwrap();
        let intermediate_issuer = Issuer::new(intermediate_params, intermediate_key);

        let mut leaf_params = CertificateParams::new(vec!["client.example.test".into()]).unwrap();
        leaf_params.serial_number = Some(SerialNumber::from_slice(&SERIAL));
        let leaf = leaf_params.signed_by(&key, &intermediate_issuer).unwrap();
        Self {
            leaf_pem: leaf.pem(),
            leaf_der: leaf.der().to_vec(),
            intermediate_pem: intermediate.pem(),
            intermediate_der: intermediate.der().to_vec(),
            key,
        }
    }

    /// The leaf followed by its intermediate, as cert-manager writes `tls.crt`.
    pub(crate) fn bundle(&self) -> String {
        format!("{}{}", self.leaf_pem, self.intermediate_pem)
    }

    /// Writes the bundle and the PKCS#8 key, returning their paths.
    pub(crate) fn write(&self, dir: &TempDir) -> (PathBuf, PathBuf) {
        (
            dir.write("tls.crt", self.bundle()),
            dir.write("tls.key", self.key.serialize_pem()),
        )
    }
}

/// `der` as a PEM block with `label`.
pub(crate) fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// The `privateKey` octets of a PKCS#8 `PrivateKeyInfo`: PKCS#1 for an RSA key.
pub(crate) fn pkcs8_inner_key(pkcs8: &[u8]) -> Vec<u8> {
    let (_, info) = parse_der(pkcs8).unwrap();
    let fields = info.as_sequence().unwrap();
    let [_, _, key, ..] = fields.as_slice() else {
        unreachable!("a PrivateKeyInfo has at least three fields")
    };
    key.as_slice().unwrap().to_vec()
}

/// An HTTP client that answers with canned responses, in order, and keeps every request.
#[derive(Debug, Clone, Default)]
pub(crate) struct FakeHttp(Arc<Mutex<FakeState>>);

#[derive(Debug, Default)]
struct FakeState {
    responses: VecDeque<(u16, String)>,
    requests: Vec<HttpRequest>,
}

impl FakeHttp {
    pub(crate) fn new<'a>(responses: impl IntoIterator<Item = (u16, &'a str)>) -> Self {
        let responses = responses
            .into_iter()
            .map(|(status, body)| (status, body.to_owned()))
            .collect();
        Self(Arc::new(Mutex::new(FakeState {
            responses,
            requests: Vec::new(),
        })))
    }

    /// Every request received so far.
    pub(crate) fn requests(&self) -> Vec<HttpRequest> {
        let state = self.0.lock().unwrap();
        state
            .requests
            .iter()
            .map(|request| request.try_clone().unwrap())
            .collect()
    }
}

impl HttpConnector for FakeHttp {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let mut state = self.0.lock().unwrap();
        state.requests.push(request);
        let answer = match state.responses.pop_front() {
            Some((status, body)) => Ok(HttpResponse::new(
                status.try_into().unwrap(),
                SdkBody::from(body),
            )),
            None => Err(ConnectorError::other(
                "no canned response left".into(),
                None,
            )),
        };
        HttpConnectorFuture::ready(answer)
    }
}

impl HttpClient for FakeHttp {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }
}
