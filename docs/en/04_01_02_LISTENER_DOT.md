# DNS over TLS (DoT) Listener

Introduction: Explains how to configure the DNS over TLS (DoT) server in lazydns. DoT provides encrypted DNS queries over TCP using TLS, standard port 853.

## Configuration Options

The `dot_server` plugin supports the following options under `args`:

- `listen`: Listen address (string). Default: "0.0.0.0:853". Supports shorthand like ":853".
- `entry`: Entry plugin name (string). Default: "main_sequence".
- `cert_file`: Path to TLS certificate file (required). Must be a valid PEM-encoded certificate.
- `key_file`: Path to TLS private key file (required). Must be a valid PEM-encoded private key.

## Examples

### Basic DoT Server

```yaml
plugins:
  - tag: dot_server
    type: dot_server
    args:
      listen: :853  # Standard DoT port
      entry: sequence_main
      cert_file: certs/cert.pem
      key_file: certs/key.pem
```

### Custom Port (for testing)

```yaml
plugins:
  - tag: dot_test
    type: dot_server
    args:
      listen: 127.0.0.1:8853  # Localhost, non-standard port
      entry: sequence_main
      cert_file: /path/to/cert.pem
      key_file: /path/to/key.pem
```

## Notes

- **Port 853**: Standard DoT port. Requires root privileges on Unix systems for port < 1024.
- **TLS Certificate**: Must be a valid certificate chain. For production, use certificates from a trusted CA. For testing, you can generate self-signed certificates.
- **Feature Required**: Enable the `dot` feature at compile time: `cargo build --features dot`.
- **Certificate Paths**: Relative paths are resolved from the config file's directory.
- **IPv6**: Use addresses like "[::]:853" for IPv6.
- **Client Support**: Most modern DNS clients (like systemd-resolved, dnscrypt-proxy) support DoT.

## Implementation Details

- Uses Rustls for TLS implementation.
- Server validates certificate and key on startup.
- Errors during TLS config loading prevent server startup.
- Integrates with the plugin system via `PluginHandler`.

See `src/server/launcher.rs` for launch logic and `src/server/dot.rs` for server implementation.