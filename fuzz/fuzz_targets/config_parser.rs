#![no_main]

use lazydns::config::Config;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz test for configuration parsing
    // Try to parse random bytes as YAML configuration
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        // This should not panic regardless of input
        let _ = Config::from_yaml(yaml_str);
    }
});
