# Edns0Opt Plugin Demo

This demo shows how to use the `edns0opt` plugin to add custom EDNS0 options to DNS queries before forwarding them to upstream servers.

## Configuration

The plugin is configured in the `config.example.yaml` file. Here's the relevant section:

```yaml
# Add EDNS0 options before forwarding (demo)
- tag: edns0_options
  type: edns0opt
  args:
    options:
      - code: 8  # EDNS Client Subnet (ECS)
        data: [0, 1, 24, 0, 192, 168, 1, 0]  # Example ECS data for 192.168.1.0/24
      - code: 10  # DNS Cookie
        data: [1, 2, 3, 4, 5, 6, 7, 8]  # Example cookie data
    preserve_existing: true
```

## Plugin Arguments

- `options`: Array of EDNS0 options to add
  - `code`: The EDNS0 option code (u16)
  - `data`: The option data as an array of bytes
- `preserve_existing`: Whether to preserve existing EDNS0 options in the query (default: true)

## Common EDNS0 Option Codes

- `8`: EDNS Client Subnet (ECS) - Used for geo-based DNS responses
- `10`: DNS Cookie - Used for DNS security
- `15`: Extended DNS Error - Used for detailed error reporting

## Usage in Sequence
C
The plugin is used in a sequence before the forward plugin:

```yaml
- tag: main_sequence
  type: sequence
  args:
    - exec: $edns0_options  # Add EDNS0 options
    - exec: $forward        # Forward the query
    - exec: accept          # Accept the response
```

## Running the Demo

1. Copy `config.example.yaml` to `config.yaml`
2. Run lazydns: `cargo run -- -c config.yaml`
3. Test with a DNS query tool like `dig`

The plugin will automatically add the configured EDNS0 options to all forwarded queries.