# Reverse Lookup Plugin

`reverse_lookup` maintains a small in-memory mapping of IP -> owner name populated from A/AAAA answers and can answer PTR queries from cache when enabled.

## Args

- `size` (int): approximate cache capacity.
- `handle_ptr` (bool): respond to PTR queries from cache.
- `ttl` (int): max TTL applied to cached entries.

## Behavior

- Call `save_ips_after` (or include plugin after response) to record IP->name mappings.
- When `handle_ptr` is enabled the plugin will return PTR answers for reverse queries if a cached mapping exists and is unexpired.

## When to use

- Use to provide fast PTR replies for hosts discovered via normal queries, useful in local networks.
- Combine with plugins like `hosts` or `forwarder` to build dynamic reverse resolution without static PTR records.