#![no_main]

use lazydns::plugins::domain_validator::DomainValidatorPlugin;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz test for domain validator
    // Try to parse random bytes as UTF-8 and validate as domain
    if let Ok(domain) = std::str::from_utf8(data) {
        let validator = DomainValidatorPlugin::default();
        // This should not panic regardless of input
        let _ = validator.validate_domain(domain);
    }
});
