use clap::{ArgEnum, Parser};
use std::process::exit;
use std::time::Duration;

/// The maximum number of hops we allow.
pub const MAX_HOPS: usize = 256;

/// The minimum TUI refresh rate.
const TUI_MIN_REFRESH_RATE_MS: Duration = Duration::from_millis(50);

/// The maximum TUI refresh rate.
const TUI_MAX_REFRESH_RATE_MS: Duration = Duration::from_millis(1000);

/// The minimum socket read timeout.
const MIN_READ_TIMEOUT_MS: Duration = Duration::from_millis(10);

/// The maximum socket read timeout.
const MAX_READ_TIMEOUT_MS: Duration = Duration::from_millis(100);

/// The minimum grace duration.
const MIN_GRACE_DURATION_MS: Duration = Duration::from_millis(10);

/// The maximum grace duration.
const MAX_GRACE_DURATION_MS: Duration = Duration::from_millis(1000);

/// The tool mode.
#[derive(Debug, Copy, Clone, ArgEnum)]
pub enum Mode {
    /// Display interactive TUI.
    Tui,
    /// Display a continuous stream of tracing data
    Stream,
    /// Generate a text table report for N cycles.
    Table,
    /// Generate a SCV report for N cycles.
    Csv,
    /// Generate a JSON report for N cycles.
    Json,
}

/// Trace a route to a host and record statistics
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// The hostname or IP to scan
    pub hostname: String,

    /// The TTL to start from
    #[clap(long, default_value_t = 1)]
    pub first_ttl: u8,

    /// The maximum number of hops
    #[clap(short = 't', long, default_value_t = 64)]
    pub max_ttl: u8,

    /// The minimum duration of every round
    #[clap(short = 'i', long, default_value = "1s")]
    pub min_round_duration: String,

    /// The maximum duration of every round
    #[clap(short = 'I', long, default_value = "1s")]
    pub max_round_duration: String,

    /// The period of time to wait for additional ICMP responses after the target has responded
    #[clap(short = 'g', long, default_value = "100ms")]
    pub grace_duration: String,

    /// The maximum number of in-flight ICMP echo requests
    #[clap(short = 'U', long, default_value_t = 24)]
    pub max_inflight: u8,

    /// The socket read timeout.
    #[clap(long, default_value = "10ms")]
    pub read_timeout: String,

    /// Preserve the screen on exit
    #[clap(long)]
    pub tui_preserve_screen: bool,

    /// The TUI refresh rate
    #[clap(long, default_value = "100ms")]
    pub tui_refresh_rate: String,

    /// Output mode
    #[clap(arg_enum, short = 'm', long, default_value = "tui")]
    pub mode: Mode,

    /// The number of report cycles to run
    #[clap(short = 'c', long, default_value_t = 10)]
    pub report_cycles: usize,
}

/// Validate `report_cycles`
pub fn validate_report_cycles(report_cycles: usize) {
    if report_cycles == 0 {
        eprintln!(
            "report_cycles ({}) must be greater than zero",
            report_cycles
        );
        exit(-1);
    }
}

/// Validate `tui_refresh_rate`
pub fn validate_tui_refresh_rate(tui_refresh_rate: Duration) {
    if tui_refresh_rate < TUI_MIN_REFRESH_RATE_MS || tui_refresh_rate > TUI_MAX_REFRESH_RATE_MS {
        eprintln!(
            "tui_refresh_rate ({:?}) must be between {:?} and {:?} inclusive",
            tui_refresh_rate, TUI_MIN_REFRESH_RATE_MS, TUI_MAX_REFRESH_RATE_MS
        );
        exit(-1);
    }
}

/// Validate `grace_duration`
pub fn validate_grace_duration(read_timeout: Duration, grace_duration: Duration) {
    if grace_duration < MIN_GRACE_DURATION_MS || grace_duration > MAX_GRACE_DURATION_MS {
        eprintln!(
            "grace_duration ({:?}) must be between {:?} and {:?} inclusive",
            read_timeout, MIN_GRACE_DURATION_MS, MAX_GRACE_DURATION_MS
        );
        exit(-1);
    }
}

/// Validate `min_round_duration` and `max_round_duration`
pub fn validate_round_duration(min_round_duration: Duration, max_round_duration: Duration) {
    if min_round_duration > max_round_duration {
        eprintln!(
            "max_round_duration ({:?}) must not be less than min_round_duration ({:?})",
            max_round_duration, min_round_duration
        );
        exit(-1);
    }
}

/// Validate `read_timeout`
pub fn validate_read_timeout(read_timeout: Duration) {
    if read_timeout < MIN_READ_TIMEOUT_MS || read_timeout > MAX_READ_TIMEOUT_MS {
        eprintln!(
            "read_timeout ({:?}) must be between {:?} and {:?} inclusive",
            read_timeout, MIN_READ_TIMEOUT_MS, MAX_READ_TIMEOUT_MS
        );
        exit(-1);
    }
}

/// Validate `max_inflight`
pub fn validate_max_inflight(max_inflight: u8) {
    if max_inflight == 0 {
        eprintln!("max_inflight ({}) must be greater than zero", max_inflight);
        exit(-1);
    }
}

/// Validate `first_ttl` and `max_ttl`
pub fn validate_ttl(first_ttl: u8, max_ttl: u8) {
    if (first_ttl as usize) < 1 || (first_ttl as usize) > MAX_HOPS {
        eprintln!("first_ttl ({first_ttl}) must be in the range 1..{MAX_HOPS}");
        exit(-1);
    }
    if (max_ttl as usize) < 1 || (max_ttl as usize) > MAX_HOPS {
        eprintln!("max_ttl ({max_ttl}) must be in the range 1..{MAX_HOPS}");
        exit(-1);
    }
    if first_ttl > max_ttl {
        eprintln!("first_ttl ({first_ttl}) must be less than or equal to max_ttl ({max_ttl})");
        exit(-1);
    }
}
