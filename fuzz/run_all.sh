#!/bin/bash
# Run all fuzz tests for lazydns

set -e

echo "Running fuzz tests for lazydns..."

# Get list of fuzz targets (run under nightly toolchain without changing global default)
targets=$(cargo +nightly fuzz list)

for target in $targets; do
    echo "========================================="
    echo "Running fuzz target: $target"
    echo "========================================="

    # Run each target for 30 seconds under nightly
    timeout 30s cargo +nightly fuzz run "$target" -- -max_total_time=30 || true

    echo "Completed fuzz target: $target"
    echo ""
done

echo "All fuzz tests completed!"