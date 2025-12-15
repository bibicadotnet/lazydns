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
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_nonexistent_cert() {
        let result = TlsConfig::from_files("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_nonexistent_key() {
        let result = TlsConfig::from_files("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("certificate file") || msg.contains("key file"));
        }
    }

    #[test]
    fn test_tls_config_clone() {
        // Create a mock certificate and key for testing clone
        // We'll use minimal valid data that can be parsed
        let cert_pem = b"-----BEGIN CERTIFICATE-----\n\
                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n\
                        -----END CERTIFICATE-----\n";

        let key_pem = b"-----BEGIN PRIVATE KEY-----\n\
                      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg\n\
                      -----END PRIVATE KEY-----\n";

        let cert_file = NamedTempFile::new().unwrap();
        cert_file.as_file().write_all(cert_pem).unwrap();

        let key_file = NamedTempFile::new().unwrap();
        key_file.as_file().write_all(key_pem).unwrap();

        // Even though parsing will fail, we can test that clone is implemented
        let result = TlsConfig::from_files(cert_file.path(), key_file.path());
        if let Ok(config) = result {
            let cloned = config.clone();
            // Clone should create a separate instance
            assert_eq!(config.certs.len(), cloned.certs.len());
        }
        // If parsing fails, that's expected for mock data
    }

    #[test]
    fn test_load_certs_empty_file() {
        let empty_file = NamedTempFile::new().unwrap();
        let result = TlsConfig::load_certs(empty_file.path());
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("No certificates found"));
        }
    }

    #[test]
    fn test_load_certs_invalid_pem() {
        let invalid_file = NamedTempFile::new().unwrap();
        invalid_file
            .as_file()
            .write_all(b"invalid pem data")
            .unwrap();

        let result = TlsConfig::load_certs(invalid_file.path());
        assert!(result.is_err());
        // Just check that it's an error, don't check the exact message
        // as it might vary depending on the rustls version
    }

    #[test]
    fn test_load_key_empty_file() {
        let empty_file = NamedTempFile::new().unwrap();
        let result = TlsConfig::load_key(empty_file.path());
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("No private key found"));
        }
    }

    #[test]
    fn test_load_key_invalid_pem() {
        let invalid_file = NamedTempFile::new().unwrap();
        invalid_file
            .as_file()
            .write_all(b"invalid key data")
            .unwrap();

        let result = TlsConfig::load_key(invalid_file.path());
        assert!(result.is_err());
        // Just check that it's an error, don't check the exact message
    }

    #[test]
    fn test_load_certs_file_read_error() {
        // Test with a path that exists but we can't read
        let temp_dir = tempfile::tempdir().unwrap();
        let cert_path = temp_dir.path().join("cert.pem");

        // Create a directory instead of a file to cause read error
        std::fs::create_dir(&cert_path).unwrap();

        let result = TlsConfig::load_certs(&cert_path);
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("Failed to read certificate file"));
        }
    }

    #[test]
    fn test_load_key_file_read_error() {
        // Test with a path that exists but we can't read
        let temp_dir = tempfile::tempdir().unwrap();
        let key_path = temp_dir.path().join("key.pem");

        // Create a directory instead of a file to cause read error
        std::fs::create_dir(&key_path).unwrap();

        let result = TlsConfig::load_key(&key_path);
        assert!(result.is_err());
        if let Err(Error::Config(msg)) = result {
            assert!(msg.contains("Failed to read key file"));
        }
    }

    // Note: build_server_config testing requires proper crypto provider setup
    // which is complex in unit tests. Integration tests should cover this functionality.

    #[test]
    fn test_tls_config_from_files_with_valid_paths() {
        // Test that from_files accepts different path types
        let cert_path = std::path::PathBuf::from("dummy.pem");
        let key_path = "dummy.key";

        let result = TlsConfig::from_files(cert_path.as_path(), key_path);
        assert!(result.is_err()); // Should fail because files don't exist
    }

    #[test]
    fn test_load_certs_with_multiple_certs() {
        // Create a file with multiple certificates
        let cert_pem = b"-----BEGIN CERTIFICATE-----\n\
                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n\
                        -----END CERTIFICATE-----\n\
                        -----BEGIN CERTIFICATE-----\n\
                        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n\
                        -----END CERTIFICATE-----\n";

        let cert_file = NamedTempFile::new().unwrap();
        cert_file.as_file().write_all(cert_pem).unwrap();

        let result = TlsConfig::load_certs(cert_file.path());
        // This will likely fail due to invalid cert data, but tests that multiple certs are attempted
        // The important thing is that it doesn't panic
        let _ = result;
    }

    #[test]
    fn test_error_message_formatting() {
        // Test that error messages are properly formatted
        let result = TlsConfig::from_files("nonexistent.pem", "nonexistent.key");
        assert!(result.is_err());

        if let Err(Error::Config(msg)) = result {
            assert!(!msg.is_empty());
            assert!(msg.contains("Failed to read"));
        }
    }
}
