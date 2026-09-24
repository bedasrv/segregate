use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use rustls::ServerConfig;

/// Persistent CA for one proxy run: generated once at startup, shared
/// read-only to sign leaves for CONNECTed hosts. A small bounded leaf cache
/// avoids repeating ECDSA work for persistent clients without allowing an
/// attacker-controlled authority set to grow memory forever.
pub struct CaAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    leaves: RwLock<HashMap<String, Arc<ServerConfig>>>,
}

impl CaAuthority {
    pub fn generate() -> Result<Self, rcgen::Error> {
        let mut params = rcgen::CertificateParams::new(vec![])?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "segregate MITM CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate()?;
        let ca_cert = params.self_signed(&ca_key)?;
        Ok(Self {
            ca_cert,
            ca_key,
            leaves: RwLock::new(HashMap::new()),
        })
    }

    /// PEM of the CA certificate, for `--ca-out` / trust stores.
    pub fn ca_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Return a cached leaf for `host`, or issue a bounded-cache leaf.
    pub fn leaf_config(&self, host: &str) -> Result<Arc<ServerConfig>, rcgen::Error> {
        if let Some(config) = self
            .leaves
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .get(host)
            .cloned()
        {
            return Ok(config);
        }

        let mut params = rcgen::CertificateParams::new(vec![host.to_owned()])?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, host);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        let leaf_key = rcgen::KeyPair::generate()?;
        let leaf = params.signed_by(&leaf_key, &self.ca_cert, &self.ca_key)?;
        let key_der = leaf_key.serialize_der();
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        let config = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![leaf.der().clone()], key)
                .map_err(|_| rcgen::Error::CouldNotParseCertificate)?,
        );

        let mut leaves = self
            .leaves
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        const MAX_LEAVES: usize = 256;
        if leaves.len() >= MAX_LEAVES
            && !leaves.contains_key(host)
            && let Some(victim) = leaves.keys().next().cloned()
        {
            leaves.remove(&victim);
        }
        leaves.insert(host.to_owned(), config.clone());
        Ok(config)
    }
}
