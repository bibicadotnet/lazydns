# Arbitrary Plugin

The `arbitrary` plugin provides a simple way to return predefined DNS resource records for matching queries. Rules may be supplied inline or loaded from files and support A, AAAA and CNAME records. This plugin is useful for tests, local overrides, and tiny authoritative responses.

## What it does

- Maps a query name to one or more preconfigured `ResourceRecord`s and returns them as the response.
- If a request contains no question, the plugin will return the first configured rule set as a fallback (useful in exec/test flows).

## Supported rule formats

- Inline `rules` (sequence of strings) or file lines in files referenced by `files`.
- Each rule line is whitespace-separated: `qname TYPE RDATA` where TYPE is `A`, `AAAA`, or `CNAME`.

Examples:

- `example.com A 192.0.2.1`
- `example.com AAAA 2001:db8::1`
- `example.com CNAME target.example.com`

Lines beginning with `#` or `;` and empty lines are ignored when loading from files.

## Configuration

- `rules` (sequence, optional): inline rule strings.
- `files` (sequence, optional): file paths containing rule lines.

Example (inline rules):

```yaml
plugins:
  - tag: arb
    type: arbitrary
    config:
      rules:
        - "example.com A 192.0.2.1"
        - "example.com CNAME cname.example.net"
```

Example (file-backed):

```yaml
plugins:
  - tag: arb-file
    type: arbitrary
    config:
      files:
        - examples/arbitrary/rules.txt
```


## Troubleshooting

- If rules do not apply, ensure qname matches exactly (case-insensitive normalization and trailing-dot handling apply).
- For file-based rules, verify file read permissions and line formats; parse errors during init will be returned.

