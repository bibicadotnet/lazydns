#![no_main]

use lazydns::dns::wire::parse_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz test for DNS message parsing
    // Try to parse random bytes as DNS message
    // This should not panic regardless of input
    let _ = parse_message(data);
});
