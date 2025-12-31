# Fuzz Testing for lazydns

This directory contains fuzz tests for the lazydns DNS server to help discover crashes, memory safety issues, and other bugs.

## Available Fuzz Targets

- **domain_validator**: Tests domain name validation logic
- **dns_parser**: Tests DNS message parsing from wire format
- **config_parser**: Tests YAML configuration parsing

## Prerequisites

- Rust nightly toolchain (required for fuzzing)
- Install cargo-fuzz: `cargo install cargo-fuzz`

## Running Fuzz Tests

### Switch to nightly Rust
```bash
rustup default nightly
```

### List available targets
```bash
cargo fuzz list
```

### Run a specific fuzz target
```bash
# Run domain validator fuzzing for 10 seconds
cargo fuzz run domain_validator -- -max_total_time=10

# Run DNS parser fuzzing with 1000 runs
cargo fuzz run dns_parser -- -runs=1000

# Run config parser fuzzing
cargo fuzz run config_parser -- -max_total_time=30
```

### Run all fuzz targets at once
```bash
./fuzz/run_all.sh
```

This script automatically switches to nightly Rust for fuzzing and back to stable afterwards.

## CI Integration

For continuous integration, you can add fuzz testing to your CI pipeline:

```yaml
# Example GitHub Actions
- name: Install cargo-fuzz
  run: cargo install cargo-fuzz

- name: Run fuzz tests
  run: |
    rustup default nightly
    for target in $(cargo fuzz list); do
        timeout 60s cargo fuzz run $target -- -max_total_time=60 || true
    done
```

## Corpus Management

Fuzzing generates test cases that can be saved and reused:

```bash
# Run fuzzing and save interesting inputs
cargo fuzz run domain_validator

# The corpus is saved in fuzz/corpus/domain_validator/
# Crashes are saved in fuzz/artifacts/domain_validator/
```

## Adding New Fuzz Targets

1. Create a new file in `fuzz_targets/`
2. Add the binary to `fuzz/Cargo.toml`
3. Implement the fuzz target using `libfuzzer_sys::fuzz_target!`

Example:
```rust
// fuzz_targets/new_target.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Your fuzzing logic here
    // This should not panic on any input
});
```

## Best Practices

1. **No panics**: Fuzz targets should handle all inputs gracefully
2. **Fast execution**: Keep fuzz targets lightweight
3. **Good coverage**: Design inputs to exercise different code paths
4. **Regular runs**: Run fuzzing regularly to catch regressions

## Troubleshooting

- **Nightly required**: Fuzzing requires Rust nightly due to unstable features
- **Memory usage**: Fuzzing can be memory-intensive, especially with ASAN
- **Time limits**: Use timeouts to prevent CI from hanging