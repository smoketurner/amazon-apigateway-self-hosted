//! Mutual TLS truststores: the PEM bundle of CA certificates, in Amazon S3,
//! that a custom domain trusts to issue its clients' certificates.
//!
//! API Gateway accepts a client certificate issued by any CA in the bundle,
//! rejects one that is expired, altered, or not chained to the bundle, and does
//! not check revocation. A bundle is at most 1 MB.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html>

use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject as _;
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::ClientCertVerifier;

/// API Gateway's limit on a truststore.
const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub(crate) enum TruststoreError {
    #[error("{0:?} is not an s3://bucket/key URI")]
    InvalidUri(String),
    #[error("could not read {location} from S3: {reason}")]
    Fetch { location: String, reason: String },
    #[error("the truststore is larger than {MAX_BUNDLE_BYTES} bytes")]
    TooLarge,
    #[error("the truststore contains no usable CA certificates")]
    Empty,
    #[error("could not build the client certificate verifier: {0}")]
    Verifier(String),
}

/// Where a domain's truststore is: `s3://bucket/key`, at an object version
/// (the latest when absent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TruststoreRef {
    bucket: String,
    key: String,
    version: Option<String>,
}

impl TruststoreRef {
    pub(crate) fn parse(uri: &str, version: Option<&str>) -> Result<Self, TruststoreError> {
        let invalid = || TruststoreError::InvalidUri(uri.to_owned());
        let (bucket, key) = uri
            .strip_prefix("s3://")
            .and_then(|rest| rest.split_once('/'))
            .filter(|(bucket, key)| !bucket.is_empty() && !key.is_empty())
            .ok_or_else(invalid)?;
        Ok(Self {
            bucket: bucket.to_owned(),
            key: key.to_owned(),
            version: version.filter(|v| !v.is_empty()).map(str::to_owned),
        })
    }

    fn location(&self) -> String {
        match self.version {
            Some(ref version) => format!("s3://{}/{} (version {version})", self.bucket, self.key),
            None => format!("s3://{}/{}", self.bucket, self.key),
        }
    }
}

/// A truststore's CA certificates.
#[derive(Debug, Clone)]
pub(crate) struct Truststore {
    bundle: Vec<u8>,
    roots: Arc<RootCertStore>,
}

impl Truststore {
    /// Reads the PEM `bundle`. Entries that are not usable CA certificates are
    /// skipped (API Gateway warns about them and keeps the rest).
    ///
    /// # Errors
    ///
    /// When no entry is usable.
    pub(crate) fn parse(bundle: &[u8]) -> Result<Self, TruststoreError> {
        let mut roots = RootCertStore::empty();
        for certificate in CertificateDer::pem_slice_iter(bundle).flatten() {
            if let Err(err) = roots.add(certificate) {
                tracing::warn!(%err, "skipping an unusable certificate in the truststore");
            }
        }
        if roots.is_empty() {
            return Err(TruststoreError::Empty);
        }
        Ok(Self {
            bundle: bundle.to_vec(),
            roots: Arc::new(roots),
        })
    }

    /// Whether `other` is the same bundle, so nothing needs to change.
    pub(crate) fn same_bundle(&self, other: &Self) -> bool {
        self.bundle == other.bundle
    }

    /// A verifier that requires a client certificate chained to this bundle.
    ///
    /// # Errors
    ///
    /// When rustls rejects the roots.
    pub(crate) fn verifier(&self) -> Result<Arc<dyn ClientCertVerifier>, TruststoreError> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        WebPkiClientVerifier::builder_with_provider(Arc::clone(&self.roots), provider)
            .build()
            .map_err(|err| TruststoreError::Verifier(err.to_string()))
    }
}

/// Reads truststores from S3.
#[derive(Debug, Clone)]
pub(crate) struct TruststoreSource {
    client: aws_sdk_s3::Client,
}

impl TruststoreSource {
    pub(crate) fn new(sdk_config: &aws_config::SdkConfig) -> Self {
        // A custom endpoint (a local S3-compatible server) is addressed by
        // path, since a bucket name cannot become a host name there.
        let config = aws_sdk_s3::config::Builder::from(sdk_config)
            .force_path_style(sdk_config.endpoint_url().is_some());
        Self {
            client: aws_sdk_s3::Client::from_conf(config.build()),
        }
    }

    /// Downloads and parses the truststore at `reference`.
    ///
    /// # Errors
    ///
    /// When S3 cannot be read, the object is too large, or it holds no usable
    /// certificates.
    pub(crate) async fn load(
        &self,
        reference: &TruststoreRef,
    ) -> Result<Truststore, TruststoreError> {
        let fetch = |reason: String| TruststoreError::Fetch {
            location: reference.location(),
            reason,
        };
        let read = async {
            let object = self
                .client
                .get_object()
                .bucket(&reference.bucket)
                .key(&reference.key)
                .set_version_id(reference.version.clone())
                .send()
                .await
                .map_err(|err| fetch(aws_sdk_s3::error::DisplayErrorContext(err).to_string()))?;
            if object
                .content_length()
                .and_then(|len| usize::try_from(len).ok())
                .is_some_and(|len| len > MAX_BUNDLE_BYTES)
            {
                return Err(TruststoreError::TooLarge);
            }
            let bytes = object
                .body
                .collect()
                .await
                .map_err(|err| fetch(err.to_string()))?
                .into_bytes();
            if bytes.len() > MAX_BUNDLE_BYTES {
                return Err(TruststoreError::TooLarge);
            }
            Ok(bytes)
        };
        let bytes = tokio::time::timeout(FETCH_TIMEOUT, read)
            .await
            .map_err(|_| fetch("timed out".to_owned()))??;
        Truststore::parse(&bytes)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;
    use crate::client_cert::tests::certificate;
    use crate::observability::testing::{MockAws, Reply};

    #[test]
    fn s3_uris_name_a_bucket_and_key_and_an_optional_version() {
        let reference = TruststoreRef::parse("s3://bucket/path/ca.pem", Some("v1")).unwrap();
        assert_eq!(reference.bucket, "bucket");
        assert_eq!(reference.key, "path/ca.pem");
        assert_eq!(reference.version.as_deref(), Some("v1"));
        assert_eq!(
            TruststoreRef::parse("s3://bucket/ca.pem", Some(""))
                .unwrap()
                .version,
            None
        );
        for bad in [
            "",
            "bucket/key",
            "s3://bucket",
            "s3://bucket/",
            "s3:///key",
            "https://b/k",
        ] {
            assert!(TruststoreRef::parse(bad, None).is_err(), "{bad}");
        }
    }

    #[test]
    fn bundles_keep_their_usable_certificates_and_reject_empty_ones() {
        let (_, first) = certificate("ca one");
        let (_, second) = certificate("ca two");
        let store = Truststore::parse(format!("junk\n{first}\n{second}").as_bytes()).unwrap();
        assert_eq!(store.roots.len(), 2);
        assert!(store.verifier().is_ok());
        assert!(matches!(
            Truststore::parse(b"no certificates here"),
            Err(TruststoreError::Empty)
        ));
        assert!(matches!(
            Truststore::parse(b""),
            Err(TruststoreError::Empty)
        ));
        let same = Truststore::parse(format!("junk\n{first}\n{second}").as_bytes()).unwrap();
        assert!(store.same_bundle(&same));
        assert!(!store.same_bundle(&Truststore::parse(first.as_bytes()).unwrap()));
    }

    #[tokio::test]
    async fn truststores_are_read_from_s3_at_the_requested_version() {
        let aws = MockAws::start().await;
        let (_, pem) = certificate("ca");
        aws.reply("/trust/ca.pem", Reply::json(&pem));
        let source = TruststoreSource::new(&aws.sdk_config());
        let reference = TruststoreRef::parse("s3://trust/ca.pem", Some("abc123")).unwrap();
        let store = source.load(&reference).await.unwrap();
        assert_eq!(store.roots.len(), 1);
        let call = aws.calls().pop().unwrap();
        assert_eq!(call.target, "/trust/ca.pem");
        assert!(call.query.as_deref().unwrap().contains("versionId=abc123"));
    }

    #[tokio::test]
    async fn s3_failures_and_bad_bundles_are_errors() {
        let aws = MockAws::start().await;
        let source = TruststoreSource::new(&aws.sdk_config());
        let reference = TruststoreRef::parse("s3://trust/ca.pem", None).unwrap();
        aws.reply("/trust/ca.pem", Reply::error("NoSuchKey"));
        assert!(matches!(
            source.load(&reference).await,
            Err(TruststoreError::Fetch { .. })
        ));
        aws.reply("/trust/ca.pem", Reply::json("not a bundle"));
        assert!(matches!(
            source.load(&reference).await,
            Err(TruststoreError::Empty)
        ));
    }
}
