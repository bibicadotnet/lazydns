# DNS over QUIC (DoQ) Listener

Introduction: Explains how to configure the DNS over QUIC (DoQ) server in lazydns. DoQ provides encrypted DNS queries over QUIC/UDP, standard port 784.

## Configuration Options

The `doq_server` plugin supports the following options under `args`:

- `listen`: Listen address (string). Default: "0.0.0.0:784". Supports shorthand like ":784".
- `entry`: Entry plugin name (string). Default: "main_sequence".
- `cert_file`: Path to TLS certificate file (required). Must be a valid PEM-encoded certificate.
- `key_file`: Path to TLS private key file (required). Must be a valid PEM-encoded private key.

## Examples

### Basic DoQ Server

```yaml
plugins:
  - tag: doq_server
    type: doq_server
    args:
      listen: :784  # Standard DoQ port
      entry: sequence_main
      cert_file: certs/cert.pem
      key_file: certs/key.pem
```

### Custom Port (for testing)

```yaml
plugins:
  - tag: doq_test
    type: doq_server
    args:
      listen: 127.0.0.1:8784  # Localhost, non-standard port
      entry: sequence_main
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

## Notes

- **Port 784**: Standard DoQ port. May require root privileges on some systems.
- **TLS Certificate**: Must be a valid certificate chain. For production, use certificates from a trusted CA. For testing, generate self-signed certificates.
- **Feature Required**: Enable the `doq` feature at compile time: `cargo build --features doq`.
- **QUIC Protocol**: Uses QUIC for transport, providing low-latency encrypted DNS.
- **Certificate Paths**: Relative paths are resolved from the config file's directory.
- **IPv6**: Use addresses like "[::]:784" for IPv6.
- **Client Support**: Limited client support currently; mainly experimental implementations.

## Implementation Details

- Uses quinn for QUIC implementation and Rustls for TLS.
- Server validates certificate and key on startup.
- DNS queries are sent over QUIC streams.
- Errors during config loading prevent server startup.
- Integrates with the plugin system via `PluginHandler`.

See `src/server/launcher.rs` for launch logic and `src/server/doq.rs` for server implementation.