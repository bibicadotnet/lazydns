# Drop Response Plugin

`drop_resp` is a tiny `exec` helper plugin that clears any existing DNS response stored in the plugin `Context`. It is useful when you want to discard a previously-produced response and continue processing with later plugins.

## Behavior

- When executed, `drop_resp` sets the current context response to `None`.
- The plugin never fails and has no configuration parameters.

## Quick (exec) setup

This plugin supports a no-argument exec quick setup; the `exec_str` is ignored.

Examples:

```yaml
# exec style (compact)
plugins:
  - exec: drop_resp

# as a configured plugin (same behavior)
  - tag: drop
    type: drop_resp
```


## When to use

- Use inside composite flows where a previously-set response must be removed before handing the request to subsequent plugins (for example, when you want to try a different upstream or re-run matching logic).

