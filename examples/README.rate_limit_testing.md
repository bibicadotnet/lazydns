# Rate Limit Testing

This directory contains tools for testing the LazyDNS rate limiting functionality.

## Files

- `ratelimit.demo.yaml` - Demo configuration with different rate limit settings
- `README.ratelimit.md` - Detailed documentation for the rate limit demo
- `test_rate_limit.sh` - Bash script for manual testing of rate limits
- `tests/integration_ratelimit.rs` - Automated integration tests

## Quick Start

1. **Start the DNS server with rate limiting:**
   ```bash
   cargo run -- --config examples/ratelimit.demo.yaml
   ```

2. **Run the automated tests:**
   ```bash
   cargo test --test integration_ratelimit
   ```

3. **Run manual tests with the script:**
   ```bash
   ./test_rate_limit.sh
   ```

## Test Configurations

The demo configuration provides three different rate limiting setups:

- **Port 5354**: Default (100 queries per 60 seconds)
- **Port 5355**: Strict (10 queries per 30 seconds)
- **Port 5356**: Lenient (500 queries per 300 seconds)

## Manual Testing

You can also test manually using `dig`:

```bash
# Test default rate limiting
for i in {1..105}; do dig @127.0.0.1 -p 5354 example.com; done

# Test strict rate limiting
for i in {1..15}; do dig @127.0.0.1 -p 5355 example.com; done

# Test lenient rate limiting
for i in {1..50}; do dig @127.0.0.1 -p 5356 example.com; done
```

When rate limiting kicks in, you'll see `REFUSED` responses instead of normal DNS answers.

## Integration Tests

The automated tests verify:
- Rate limiting works for different configurations
- Successful queries are allowed within limits
- Excess queries are properly refused
- Rate limit windows reset correctly over time

Run with verbose output to see detailed results:
```bash
cargo test --test integration_ratelimit -- --nocapture
```