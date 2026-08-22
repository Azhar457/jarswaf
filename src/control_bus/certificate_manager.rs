use crate::tls::LocalCA;
use tracing::info;

/// Manages TLS certificates
pub struct CertificateManager {
    cert_dir: String,
    tls_mode: String,
}

impl CertificateManager {
    pub fn new(cert_dir: String, tls_mode: String) -> Self {
        Self { cert_dir, tls_mode }
    }

    pub fn cert_dir(&self) -> &str {
        &self.cert_dir
    }

    pub fn tls_mode(&self) -> &str {
        &self.tls_mode
    }

    /// Ensure local CA exists
    pub async fn ensure_ca(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.tls_mode == "disabled" {
            return Ok(());
        }

        info!(
            "Certificate manager initializing in {} (mode: {})",
            self.cert_dir, self.tls_mode
        );
        let ca = LocalCA::new(&self.cert_dir);
        ca.ensure_ca()?;
        Ok(())
    }

    /// Get certificate for a domain
    pub async fn get_certificate(
        &self,
        domain: &str,
    ) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
        if self.tls_mode == "disabled" {
            return Err("TLS is disabled".into());
        }

        let ca = LocalCA::new(&self.cert_dir);
        let (certs, key) = ca.generate_server_cert(domain)?;
        let cert_der = certs
            .first()
            .map(|c| c.to_vec())
            .ok_or("Empty certificate chain")?;
        let key_der = key.secret_der().to_vec();
        Ok((cert_der, key_der))
    }
}
