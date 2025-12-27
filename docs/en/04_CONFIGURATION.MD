# Configuration (Core)

Overview of `config.yaml` structure.

## Top-level fields
- `servers` — server listener configs (UDP/TCP/DoH/DoT/DoQ)
- `plugins` — plugin lists and config
- `logging` — `LogConfig` options
- `monitoring` — metrics and admin server options

## Example: minimal `config.yaml`
```yaml
logging:
  level: info
servers:
  - type: udp
    listen: 0.0.0.0:5353
    plugins: []
```

## Environment overrides
How to use environment variables to patch config values.

---

TODO: Link plugin config reference and admin API.