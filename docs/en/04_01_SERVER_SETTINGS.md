# Server Settings

This section covers the configuration of DNS server listeners in lazydns. All server types (UDP, TCP, DoT, DoH, DoQ) are implemented as plugins in the plugin system, allowing flexible configuration and integration with the DNS processing pipeline.

## Server Listener Types

The following server listeners are available as plugins:

- **UDP and TCP Listeners**: Basic DNS servers for standard UDP/TCP protocols.
- **DNS over TLS (DoT)**: Encrypted DNS over TCP using TLS.
- **DNS over HTTPS (DoH)**: Encrypted DNS over HTTPS.
- **DNS over QUIC (DoQ)**: Encrypted DNS over QUIC/UDP.

Each listener plugin can be configured with:
- Listen address and port
- Entry plugin for DNS processing
- TLS certificates/keys (for encrypted protocols)

## See Also

- [UDP and TCP Listener](04_01_01_LISTENER_UDP_TCP.md)
- [DNS over TLS (DoT) Listener](04_01_02_LISTENER_DOT.md)
- [DNS over HTTPS (DoH) Listener](04_01_03_LISTENER_DOH.md)
- [DNS over QUIC (DoQ) Listener](04_01_04_LISTENER_DOQ.md)