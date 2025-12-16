use pico_args::Arguments;

/// Parsed command-line options
pub struct Args {
    pub config: String,
    pub dir: Option<String>,
    pub log_level: String,
    pub verbose: bool,
}

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

/// Parse CLI arguments using `pico-args`.
/// Returns `None` if help was printed and the caller should exit gracefully.
pub fn parse_args() -> Option<Args> {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.len() <= 1 {
        print_help();
        return None;
    }

    let mut pargs = Arguments::from_env();
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
