use rustls::ServerConfig;

/// Persistent CA for one proxy run: generated once at startup, shared
/// read-only (`Arc`, never mutated) to sign a leaf per CONNECTed host.
/// Export the PEM via `--ca-out` so clients can trust it once instead of
/// passing `--no-check-certificate` for every download.
pub struct CaAuthority {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
}

impl CaAuthority {
    pub fn generate() -> Result<Self, rcgen::Error> {
        let mut params = rcgen::CertificateParams::new(vec![])?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "segmented-proxy MITM CA");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];
        let ca_key = rcgen::KeyPair::generate()?;
        let ca_cert = params.self_signed(&ca_key)?;
        Ok(Self { ca_cert, ca_key })
    }

    /// PEM of the CA certificate, for `--ca-out` / trust stores.
    pub fn ca_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Throwaway leaf for `host` (SAN = DNS or IP), signed by this CA.
    /// No cache: issuance is sub-millisecond ECDSA, nothing to lock.
    pub fn leaf_config(&self, host: &str) -> Result<ServerConfig, rcgen::Error> {
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
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf.der().clone()], key)
            .map_err(|_| rcgen::Error::CouldNotParseCertificate)
    }
}
