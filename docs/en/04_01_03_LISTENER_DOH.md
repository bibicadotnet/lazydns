# DNS over HTTPS (DoH) Listener

Introduction: Explains how to configure the DNS over HTTPS (DoH) server in lazydns. DoH provides encrypted DNS queries over HTTPS, standard port 443.

## Configuration Options

The `doh_server` plugin supports the following options under `args`:

- `listen`: Listen address (string). Default: "0.0.0.0:443". Supports shorthand like ":443".
- `entry`: Entry plugin name (string). Default: "main_sequence".
- `cert_file`: Path to TLS certificate file (required). Must be a valid PEM-encoded certificate.
- `key_file`: Path to TLS private key file (required). Must be a valid PEM-encoded private key.

## Examples

### Basic DoH Server

```yaml
plugins:
  - tag: doh_server
    type: doh_server
    args:
      listen: :443  # Standard HTTPS port
      entry: sequence_main
      cert_file: certs/cert.pem
      key_file: certs/key.pem
```

### Custom Port (for testing)

```yaml
plugins:
  - tag: doh_test
    type: doh_server
    args:
      listen: 127.0.0.1:8443  # Localhost, non-standard port
      entry: sequence_main
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

## Notes

- **Port 443**: Standard HTTPS port. Requires root privileges on Unix systems.
- **TLS Certificate**: Must be a valid certificate chain. For production, use certificates from a trusted CA. For testing, generate self-signed certificates.
- **Feature Required**: Enable the `doh` feature at compile time: `cargo build --features doh`.
- **HTTP/2**: DoH uses HTTP/2 over TLS. Clients send DNS queries as HTTP POST requests to `/dns-query`.
- **Certificate Paths**: Relative paths are resolved from the config file's directory.
- **IPv6**: Use addresses like "[::]:443" for IPv6.
- **Client Support**: Browsers and DNS clients like curl, dnscrypt-proxy support DoH.

## Implementation Details

- Uses Hyper for HTTP/2 server and Rustls for TLS.
- Server validates certificate and key on startup.
- DNS queries are encoded in HTTP POST bodies (application/dns-message).
- Errors during TLS config loading prevent server startup.
- Integrates with the plugin system via `PluginHandler`.

See `src/server/launcher.rs` for launch logic and `src/server/doh.rs` for server implementation.