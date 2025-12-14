# LazyDNS Example Configuration

This directory contains a complete working example of LazyDNS configuration based on the [lazymosdns](https://github.com/lazywalker/lazymosdns) setup.

## Features Demonstrated

- **DNS Caching**: Cache query results for faster responses
- **Multiple Upstreams**: Forward queries to both local (CN) and remote (international) DNS servers
- **Domain Lists**: Separate handling for CN domains, GFW domains, and ad domains
- **IP Lists**: China IP detection and whitelisting
- **Hosts File**: Custom DNS records with auto-reload support
- **Auto-Reload**: All data provider plugins (hosts, domain_set, ip_set) support automatic file reloading
- **Fallback**: Intelligent fallback between local and remote DNS servers
- **RouterOS Integration**: Add domains to RouterOS address lists (optional)

## Quick Start

### 1. Run the Example

From the repository root:

```bash
target/release/lazydns -c config.yaml -d examples/etc/
```

### 2. Test with dig

Test basic DNS resolution:

```bash
# Test localhost resolution (from hosts.txt)
dig @127.0.0.1 -p 5354 localhost

# Test a CN domain (should use local DNS)
dig @127.0.0.1 -p 5354 baidu.com

# Test an international domain (should use remote DNS)
dig @127.0.0.1 -p 5354 google.com

# Test AAAA (IPv6) query
dig @127.0.0.1 -p 5354 AAAA google.com
```

### 3. Test with nslookup

```bash
# Test basic resolution
nslookup -port=5354 localhost 127.0.0.1

# Test domain resolution
nslookup -port=5354 baidu.com 127.0.0.1
```

## Configuration Files

### Main Configuration

- **config.yaml**: Main configuration file defining all plugins and their execution flow

### Data Files

- **hosts.txt**: Custom hosts file for local DNS resolution
- **hosts-github.txt**: GitHub-related hosts entries
- **direct-list.txt**: List of domains that should use local (CN) DNS servers
- **apple-cn.txt**: Apple domains for CN region
- **my-domain-list.txt**: Custom domain list
- **proxy-list.txt**: Domains that should use remote DNS servers (GFW list)
- **proxy-ext-list.txt**: Extended GFW domain list
- **reject-list.txt**: Ad/tracking domains to block
- **china-ip-list.txt**: China IP address ranges (CIDR format)
- **white-ip-list.txt**: Whitelisted IP addresses
- **gfw.txt**: GFW domain list (alternative format)

## Plugin Configuration

### Cache Plugin

Caches DNS responses for faster lookups:

```yaml
- tag: cache
  type: cache
  args:
    size: 10240
    lazy_cache_ttl: 86400
```

### Forward Plugins

Forward queries to upstream DNS servers:

```yaml
- tag: forward_local
  type: forward
  args:
    concurrent: 2
    upstreams:
      - addr: udp://119.29.29.29  # DNSPod
      - addr: udp://223.5.5.5      # AliDNS

- tag: forward_remote
  type: forward
  args:
    concurrent: 2
    upstreams:
      - addr: tcp://8.8.8.8        # Google DNS
      - addr: tcp://1.1.1.1        # Cloudflare DNS
```

### Hosts Plugin (with Auto-Reload)

Load custom DNS records from files:

```yaml
- tag: hosts
  type: hosts
  args:
    auto_reload: true
    files:
      - "hosts.txt"
      - "hosts-github.txt"
```

### Domain Set Plugins (with Auto-Reload)

Load domain lists for matching:

```yaml
- tag: cn-domain-list
  type: domain_set
  args:
    auto_reload: true
    files:
      - direct-list.txt
      - apple-cn.txt
      - my-domain-list.txt
```

### IP Set Plugin (with Auto-Reload)

Load IP/CIDR lists for matching:

```yaml
- tag: local_ip
  type: ip_set
  args:
    auto_reload: true
    files:
      - china-ip-list.txt
      - white-ip-list.txt
```

### Sequence Plugin

Define execution flows:

```yaml
- tag: main_sequence
  type: sequence
  args:
    - exec: $hosts
    - matches: has_resp
      exec: accept
    - matches: qname $cn-domain-list
      exec: $forward_local
    - exec: $fallback
```

### Fallback Plugin

Provide fallback between DNS servers:

```yaml
- tag: fallback
  type: fallback
  args:
    primary: local_sequence
    secondary: remote_sequence
    threshold: 500
    always_standby: true
```

### Server Plugins

Start DNS servers:

```yaml
- tag: udp_server
  type: udp_server
  args:
    entry: main_sequence
    listen: :5354

- tag: tcp_server
  type: tcp_server
  args:
    entry: main_sequence
    listen: :5354
```

## Auto-Reload Testing

The hosts, domain_set, and ip_set plugins support automatic file reloading. To test:

1. Start the server:
   ```bash
   cd example
   ../target/debug/lazydns -c config.yaml
   ```

2. In another terminal, modify a hosts file:
   ```bash
   echo "1.2.3.4 test.example.com" >> example/hosts.txt
   ```

3. Watch the logs for reload messages:
   ```
   INFO hosts: scheduled reload: invoking callback file="hosts.txt"
   INFO hosts: scheduled auto-reload completed filename="hosts.txt" duration=123μs
   ```

4. Test the new entry:
   ```bash
   dig @127.0.0.1 -p 5354 test.example.com
   ```

## Ports

The example uses port **5354** instead of the standard port 53 to avoid requiring root privileges. For production use:

1. Change `listen: :5354` to `listen: :53` in config.yaml
2. Run with `sudo` or configure appropriate capabilities

## RouterOS Integration

The `ros_addrlist` plugin is configured but requires a RouterOS instance. Update the configuration with your RouterOS details:

```yaml
- tag: add_gfwlist
  type: ros_addrlist
  args:
    addrlist: "mosdns-gfwlist"
    server: "http://YOUR_ROUTER_IP:80"
    user: "YOUR_USERNAME"
    passwd: "YOUR_PASSWORD"
    mask4: 24
    mask6: 32
```

## Logging

Control log level via environment variable or command-line:

```bash
# Using environment variable
RUST_LOG=debug ../target/debug/lazydns -c config.yaml

# Using command-line flag
../target/debug/lazydns -c config.yaml --log-level debug
```

## Troubleshooting

### Port Already in Use

If you see "Address already in use", another process is using port 5354:

```bash
# Find what's using the port
lsof -i :5354

# Kill the process or change the port in config.yaml
```

### File Not Found Errors

Ensure you're running from the example directory:

```bash
cd example
../target/debug/lazydns -c config.yaml
```

### No Response from Server

Check that the server started successfully and is listening:

```bash
# Check if port is listening
netstat -tuln | grep 5354

# Or with ss
ss -tuln | grep 5354
```

## Performance Tips

1. **Cache Size**: Increase cache size for better hit rates
2. **Concurrent Queries**: Adjust concurrent upstream queries based on your network
3. **File Watching**: Disable auto_reload in production if files rarely change

## License

This example configuration is provided as-is for demonstration purposes.
