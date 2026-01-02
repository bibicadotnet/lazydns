
# Logging Usage Guide

Introduction: Explains how to control lazydns logging via config, environment variables, or command line.

## Main config options

The `log` section in config file supports:

- `level`: `trace|debug|info|warn|error`, default level for lazydns.
- `format`: `text` (default) or `json`. `json` outputs structured logs.
- `file`: optional, write to file (append). If unset, output to stdout.
- `rotate`: optional, `daily` or `hourly`, enables rotation by local time.
- `rotate_dir`: optional, overrides rotation directory, defaults to `file`'s parent.

## Precedence

Logging level determined by (in order):
1. Environment variable `RUST_LOG` (if set and non-empty, used verbatim).
2. Command line `-v`/`-vv` etc. (when `RUST_LOG` not set):
   - No `-v`: use `warn,lazydns=<config.level>` (external crates stay quiet).
   - `-v`: set lazydns to `debug`.
   - `-vv`: set lazydns to `trace`.
   - `-vvv` or more: global `trace` (includes external crates).
3. Config file `level`.

## File logging and rotation

- If `log-file` feature is enabled, uses non-blocking file appender with background guard to prevent log loss on exit.
- `rotate: daily` generates `filename.YYYY-MM-DD`; `hourly` generates `filename.YYYY-MM-DD-HH`.
- If `log-file` feature not enabled but `file` configured, warns and ignores file writing (only stdout).

## Time and format

- Time uses RFC3339-like format with millisecond precision. Uses local time if available, else UTC.
- ANSI colors disabled when writing to file.

## Quick example (config snippet)

```yaml
log:
  level: debug
  format: text
  file: /var/log/lazydns/lazydns.log
  # rotate: daily
```

## Runtime examples

- Override all logs with env:
  - `RUST_LOG=trace ./lazydns`
- Increase this program's logs with CLI:
  - `./lazydns -v` (lazydns shows debug)
  - `./lazydns -vv` (lazydns shows trace)

## Troubleshooting

- Configured `file` but no logs in file: Ensure binary built with `log-file` feature (else ignored).
- Incorrect time: Check host timezone and local offset availability.
- Invalid `RUST_LOG`: Falls back to `warn,lazydns=<config.level>` with warning.
- No logs shown: Ensure log level not set too high; try lowering level via env or CLI.