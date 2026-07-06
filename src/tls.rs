use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::Path;

#[allow(dead_code)]
pub struct LocalCA {
    cert_path: String,
    key_path: String,
}

#[allow(dead_code)]
impl LocalCA {
    pub fn new(cert_dir: &str) -> Self {
        // Securely ensure path exists and canonicalize to avoid path traversal
        let _ = fs::create_dir_all(cert_dir);
        let canonical_path = Path::new(cert_dir)
            .canonicalize()
            .unwrap_or_else(|_| std::path::PathBuf::from(cert_dir));
        let cert_path = canonical_path.join("ca.crt").to_string_lossy().to_string();
        let key_path = canonical_path.join("ca.key").to_string_lossy().to_string();
        Self {
            cert_path,
            key_path,
        }
    }

    pub fn ensure_ca(&self) -> Result<(), Box<dyn std::error::Error>> {
        if Path::new(&self.cert_path).exists() && Path::new(&self.key_path).exists() {
            return Ok(());
        }

        // Buat parent directory jika belum ada
        if let Some(parent) = Path::new(&self.cert_path).parent() {
            fs::create_dir_all(parent)?;
        }

        let mut params = CertificateParams::new(vec!["jarsWAF Local CA".to_string()])?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let key_pair = KeyPair::generate()?;
        let cert = params.self_signed(&key_pair)?;

        fs::write(&self.cert_path, cert.pem())?;
        fs::write(&self.key_path, key_pair.serialize_pem())?;

        println!("Local CA generated at: {}", self.cert_path);
        println!("Install this CA on your devices to trust jarsWAF certificates");

        Ok(())
    }

    pub fn generate_server_cert(
        &self,
        domain: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), Box<dyn std::error::Error>>
    {
        let ca_cert_pem = fs::read_to_string(&self.cert_path)?;
        let ca_key_pem = fs::read_to_string(&self.key_path)?;

        let ca_key = KeyPair::from_pem(&ca_key_pem)?;
        let ca = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)?;

        let mut server_params =
            CertificateParams::new(vec![domain.to_string(), "localhost".to_string()])?;
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &ca)?;

        let cert_der = CertificateDer::from(server_cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(server_key.serialize_der().into());

        Ok((vec![cert_der], key_der))
    }

    pub fn generate_and_save_pem(
        &self,
        domains: Vec<String>,
        cert_path: &str,
        key_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ca_cert_pem = fs::read_to_string(&self.cert_path)?;
        let ca_key_pem = fs::read_to_string(&self.key_path)?;

        let ca_key = KeyPair::from_pem(&ca_key_pem)?;
        let ca = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key)?;

        let mut server_params = CertificateParams::new(domains)?;
        server_params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let server_key = KeyPair::generate()?;
        let server_cert = server_params.signed_by(&server_key, &ca)?;

        fs::write(cert_path, server_cert.pem())?;
        fs::write(key_path, server_key.serialize_pem())?;

        Ok(())
    }
}
