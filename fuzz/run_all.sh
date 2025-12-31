#!/bin/bash
# Run all fuzz tests for lazydns

set -e

echo "Running fuzz tests for lazydns..."

# Check if we're on nightly, switch if needed
if ! rustc --version | grep -q nightly; then
    echo "Switching to nightly Rust for fuzzing..."
    rustup default nightly
    # Restore stable after fuzzing
    trap "rustup default stable" EXIT
fi

# Get list of fuzz targets
targets=$(cargo fuzz list)

for target in $targets; do
    echo "========================================="
    echo "Running fuzz target: $target"
    echo "========================================="

    # Run each target for 30 seconds
    timeout 30s cargo fuzz run "$target" -- -max_total_time=30 || true

    echo "Completed fuzz target: $target"
    echo ""
done

echo "All fuzz tests completed!"