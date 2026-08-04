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
        write_secure_private_key(&self.key_path, &key_pair.serialize_pem())?;

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
        write_secure_private_key(key_path, &server_key.serialize_pem())?;

        Ok(())
    }
}

/// Securely writes private key to filesystem with 0o600 permissions (Unix) to prevent unauthorized local reads
fn write_secure_private_key(path: &str, content: &str) -> std::io::Result<()> {
    fs::write(path, content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_ca_generation_and_key_permissions() {
        let tmp_dir = std::env::temp_dir().join(format!("jarswaf_tls_test_{}", std::process::id()));
        let ca = LocalCA::new(tmp_dir.to_str().unwrap());
        let res = ca.ensure_ca();
        assert!(res.is_ok());

        assert!(Path::new(&ca.cert_path).exists());
        assert!(Path::new(&ca.key_path).exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&ca.key_path).expect("get key metadata");
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "Private key permissions should be 0o600");
        }

        // Cleanup
        let _ = fs::remove_dir_all(tmp_dir);
    }
}
