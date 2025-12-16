//! Lightweight command-line parsing helpers for lazydns.
//!
//! This module provides a minimal CLI parser implemented with `pico-args`.
//! It exposes `parse_args()` for normal execution (reading the process
//! arguments) and `parse_args_from_vec()` which accepts an explicit
//! `Vec<String>` for easier unit testing.

use pico_args::Arguments;

/// Parsed command-line options.
///
/// This structure contains the small set of options used by the
/// `lazydns` binary. Fields are public for easy access from `main`.
pub struct Args {
    /// Path to configuration file (default: `config.yaml`).
    pub config: String,

    /// Optional working directory to `chdir` into before startup.
    pub dir: Option<String>,

    /// Desired logging level (e.g. `info`, `debug`).
    pub log_level: String,

    /// Whether verbose mode is enabled (sets log level to `debug`).
    pub verbose: bool,
}

/// Print a short help text to stdout.
///
/// This is intentionally minimal to avoid pulling a heavy CLI help
/// generation dependency into the binary.
pub fn print_help() {
    println!("lazydns {}\n", env!("CARGO_PKG_VERSION"));
    println!("Usage: lazydns [OPTIONS]\n");
    println!("OPTIONS:");
    println!("  -c, --config <file>       Configuration file path (default: config.yaml)");
    println!("  -d, --dir <dir>           Working directory");
    println!(
        "  -l, --log-level <level>   Log level (trace, debug, info, warn, error) (default: info)"
    );
    println!("  -v, --verbose             Enable verbose output (sets log level to debug)");
    println!("  -h, --help                Print this help message");
}

/// Parse CLI arguments using `pico-args` from the current process args.
///
/// Returns `None` when help was printed (caller should exit gracefully).
pub fn parse_args() -> Option<Args> {
    let raw_args: Vec<String> = std::env::args().collect();
    parse_args_from_vec(raw_args)
}

/// Helper variant that accepts an explicit `Vec<String>` for easier testing.
///
/// The provided vector should mimic `std::env::args()` output where the
/// first element is the program name.
pub fn parse_args_from_vec(raw_args: Vec<String>) -> Option<Args> {
    if raw_args.len() <= 1 {
        print_help();
        return None;
    }

    let os_args: Vec<std::ffi::OsString> =
        raw_args.into_iter().map(std::ffi::OsString::from).collect();
    let mut pargs = Arguments::from_vec(os_args);
    if pargs.contains(["-h", "--help"]) {
        print_help();
        return None;
    }

    let config = match pargs.opt_value_from_str(["-c", "--config"]) {
        Ok(Some(s)) => s,
        _ => "config.yaml".to_string(),
    };

    let dir = match pargs.opt_value_from_str(["-d", "--dir"]) {
        Ok(Some(s)) => Some(s),
        _ => None,
    };

    let log_level = match pargs.opt_value_from_str(["-l", "--log-level"]) {
        Ok(Some(s)) => s,
        _ => "info".to_string(),
    };

    let verbose = pargs.contains(["-v", "--verbose"]);

    Some(Args {
        config,
        dir,
        log_level,
        verbose,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_none_and_prints_help_with_no_args() {
        let args = vec!["lazydns".to_string()];
        let res = parse_args_from_vec(args);
        assert!(res.is_none());
    }

    #[test]
    fn returns_none_on_help_flag() {
        let args = vec!["lazydns".to_string(), "--help".to_string()];
        let res = parse_args_from_vec(args);
        assert!(res.is_none());
    }

    #[test]
    fn parses_all_options() {
        let args = vec![
            "lazydns".to_string(),
            "-c".to_string(),
            "myconf.yaml".to_string(),
            "-d".to_string(),
            "/tmp".to_string(),
            "-l".to_string(),
            "debug".to_string(),
            "-v".to_string(),
        ];

        let res = parse_args_from_vec(args).expect("should parse args");
        assert_eq!(res.config, "myconf.yaml");
        assert_eq!(res.dir.as_deref(), Some("/tmp"));
        assert_eq!(res.log_level, "debug");
        assert!(res.verbose);
    }

    #[test]
    fn uses_defaults_when_options_missing() {
        let args = vec![
            "lazydns".to_string(),
            "-c".to_string(),
            "cfg.yml".to_string(),
        ];
        let res = parse_args_from_vec(args).expect("should parse");
        assert_eq!(res.config, "cfg.yml");
        assert_eq!(res.log_level, "info");
        assert!(!res.verbose);
    }
}
