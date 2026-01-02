# RouterOS Address List Plugin

`ros_addrlist` collects IPs from responses and (optionally) notifies a RouterOS helper server or logs additions. This is a lightweight implementation intended to integrate with RouterOS address lists.

## Args

- `list_name` (string): address list name
- `track_responses` (bool): whether to collect from responses
- `server` / `user` / `passwd`: optional HTTP helper endpoint and credentials
- `mask4` / `mask6`: masks to apply when adding prefixes

## Behavior

- Extracts IPs from answers and either calls the configured helper server or logs the additions.

## When to use

- Use when integrating DNS-driven IP lists with RouterOS devices or a helper service.
- Useful for dynamic firewall rules, blocking, or routing based on DNS responses.