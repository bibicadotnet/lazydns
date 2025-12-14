//! TLS configuration for encrypted DNS protocols
//!
//! This module provides TLS configuration support for DoT (DNS over TLS)
//! and DoH (DNS over HTTPS) servers.

use crate::error::Error;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// TLS configuration for encrypted DNS servers
pub struct TlsConfig {
    /// Server certificates
    pub certs: Vec<CertificateDer<'static>>,
    /// Private key
    pub key: PrivateKeyDer<'static>,
}

impl Clone for TlsConfig {
    fn clone(&self) -> Self {
        Self {
            certs: self.certs.clone(),
            key: self.key.clone_key(),
        }
    }
}

impl TlsConfig {
    /// Create a new TLS configuration from certificate and key files
    ///
    /// # Arguments
    ///
    /// * `cert_path` - Path to PEM-encoded certificate file
    /// * `key_path` - Path to PEM-encoded private key file
    ///
    /// # Example
    ///
    /// ```no_run
    /// use lazydns::server::TlsConfig;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let tls = TlsConfig::from_files("cert.pem", "key.pem")?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_files(
        cert_path: impl AsRef<Path>,
        key_path: impl AsRef<Path>,
    ) -> Result<Self, Error> {
        let certs = Self::load_certs(cert_path)?;
        let key = Self::load_key(key_path)?;

        Ok(Self { certs, key })
    }

    /// Load certificates from a PEM file
    fn load_certs(path: impl AsRef<Path>) -> Result<Vec<CertificateDer<'static>>, Error> {
        let cert_file = fs::read(path.as_ref())
            .map_err(|e| Error::Config(format!("Failed to read certificate file: {}", e)))?;

        let certs = rustls_pemfile::certs(&mut &cert_file[..])
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| Error::Config(format!("Failed to parse certificate: {}", e)))?;

        if certs.is_empty() {
            return Err(Error::Config("No certificates found in file".to_string()));
        }

        Ok(certs)
    }

    /// Load private key from a PEM file
    fn load_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, Error> {
        let key_file = fs::read(path.as_ref())
            .map_err(|e| Error::Config(format!("Failed to read key file: {}", e)))?;

        // Try to parse as PKCS8 first, then RSA
        let key = rustls_pemfile::private_key(&mut &key_file[..])
            .map_err(|e| Error::Config(format!("Failed to parse private key: {}", e)))?
            .ok_or_else(|| Error::Config("No private key found in file".to_string()))?;

        Ok(key)
    }

    /// Create a rustls server configuration
    pub fn build_server_config(&self) -> Result<Arc<rustls::ServerConfig>, Error> {
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(self.certs.clone(), self.key.clone_key())
            .map_err(|e| Error::Config(format!("Failed to build TLS config: {}", e)))?;

        Ok(Arc::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_nonexistent_cert() {
        let result = TlsConfig::from_files("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());
    }

    // Note: Full TLS testing requires certificate files which we don't have in tests
    // Integration tests with actual certificates should be done separately
}
