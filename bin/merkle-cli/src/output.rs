//! Terminal output helpers: human-readable tables, JSON, and plain modes.

use std::io::{self, Write as _};

use anyhow::Context as _;

/// Output format selected via `--output`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum OutputFormat {
    /// Colorised, aligned, human-readable (default).
    #[default]
    Human,
    /// Machine-readable JSON (compact).
    Json,
    /// Headerless, tab-separated plain text.
    Plain,
}

/// Print a JSON value according to the requested output format.
///
/// - `Human`/`Plain`: pretty-print each top-level key on its own line.
/// - `Json`: emit compact JSON to stdout.
pub fn print_value(value: &serde_json::Value, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, value).context("writing JSON to stdout")?;
            writeln!(stdout).context("writing newline")?;
        }
        OutputFormat::Human => print_human(value),
        OutputFormat::Plain => print_plain(value),
    }
    Ok(())
}

/// Print a success message to stdout.
pub fn print_ok(msg: &str) {
    println!("ok: {msg}");
}

/// Print an error message to stderr.
#[expect(dead_code, reason = "used by command modules in future phases")]
pub fn print_err(msg: &str) {
    eprintln!("error: {msg}");
}

/// Print a warning to stderr.
#[expect(dead_code, reason = "used by command modules in future phases")]
pub fn print_warn(msg: &str) {
    eprintln!("warn: {msg}");
}

// ---------------------------------------------------------------------------
// Internal rendering helpers
// ---------------------------------------------------------------------------

fn print_human(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let key_width = map.keys().map(String::len).max().unwrap_or(0);
            for (key, val) in map {
                let rendered = render_scalar(val);
                println!("{key:<key_width$}  {rendered}");
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                println!("--- [{i}] ---");
                print_human(item);
            }
        }
        other => println!("{}", render_scalar(other)),
    }
}

fn print_plain(value: &serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                println!("{key}\t{}", render_scalar(val));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                print_plain(item);
            }
        }
        other => println!("{}", render_scalar(other)),
    }
}

fn render_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "(null)".to_owned(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        other => serde_json::to_string(other).unwrap_or_else(|_| "(error)".to_owned()),
    }
}
