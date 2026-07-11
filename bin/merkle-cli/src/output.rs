//! Terminal output helpers: human-readable tables, JSON, and plain modes.

use std::io::{self, Write as _};

use anyhow::Context as _;
use merkle_companion_client::dto::DoctorResponse;

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

/// Print a `GET /v1/agent/doctor` response: one line per check (name,
/// status, optional message) followed by a final `overall` line.
///
/// - `Human`: key column aligned to the widest check name, mirroring
///   [`print_human`]'s key/value alignment.
/// - `Plain`: headerless, tab-separated, mirroring [`print_plain`].
/// - `Json`: the raw [`DoctorResponse`] serialized compactly.
pub fn print_doctor(doctor: &DoctorResponse, format: OutputFormat) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            let mut stdout = io::stdout().lock();
            serde_json::to_writer(&mut stdout, doctor).context("writing JSON to stdout")?;
            writeln!(stdout).context("writing newline")?;
        }
        OutputFormat::Human => {
            for line in doctor_lines_human(doctor) {
                println!("{line}");
            }
        }
        OutputFormat::Plain => {
            for line in doctor_lines_plain(doctor) {
                println!("{line}");
            }
        }
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
                let rendered = render_human_field(key, val);
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
                // Plain stays machine-friendly: raw integers, not pretty units.
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

/// Human-mode field renderer: key-aware pretty-printing for status-like objects.
fn render_human_field(key: &str, val: &serde_json::Value) -> String {
    // `db_size_bytes`, `disk_free_bytes`, etc. → "228.2 KB", "2.18 TB"
    if key.ends_with("_bytes") {
        if let Some(n) = val.as_u64() {
            return format_bytes(n);
        }
    }
    // `warnings: ["…"]` → plain text, not a JSON array dump
    if key == "warnings" {
        return render_string_list(val);
    }
    render_scalar(val)
}

fn render_scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "(null)".to_owned(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(items) if items.is_empty() => "(none)".to_owned(),
        serde_json::Value::Array(items) if items.iter().all(serde_json::Value::is_string) => {
            render_string_list(v)
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "(error)".to_owned()),
    }
}

/// Format a byte count for operators (binary units, base 1024).
///
/// Examples: `0 B`, `512 B`, `228.2 KB`, `1.50 MB`, `2.18 TB`.
fn format_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut value = n as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value >= 100.0 {
        format!("{value:.0} {}", UNITS[unit])
    } else if value >= 10.0 {
        format!("{value:.1} {}", UNITS[unit])
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

/// Render a JSON string array as operator-friendly text.
fn render_string_list(v: &serde_json::Value) -> String {
    let Some(items) = v.as_array() else {
        return render_scalar(v);
    };
    if items.is_empty() {
        return "(none)".to_owned();
    }
    let parts: Vec<&str> = items
        .iter()
        .filter_map(serde_json::Value::as_str)
        .collect();
    if parts.is_empty() {
        return serde_json::to_string(v).unwrap_or_else(|_| "(error)".to_owned());
    }
    if parts.len() == 1 {
        return parts[0].to_owned();
    }
    let mut out = format!("({} items)", parts.len());
    for p in parts {
        out.push_str("\n                      - ");
        out.push_str(p);
    }
    out
}

/// Column width for the doctor check-name column: the widest check name, or
/// `"overall"` if that happens to be wider (empty check list).
fn doctor_name_width(doctor: &DoctorResponse) -> usize {
    doctor
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(0)
        .max("overall".len())
}

fn doctor_lines_human(doctor: &DoctorResponse) -> Vec<String> {
    let width = doctor_name_width(doctor);
    let mut lines: Vec<String> = doctor
        .checks
        .iter()
        .map(|check| match &check.message {
            Some(msg) => format!("{:<width$}  {:<4}  {msg}", check.name, check.status),
            None => format!("{:<width$}  {}", check.name, check.status),
        })
        .collect();
    lines.push(format!("{:<width$}  {}", "overall", doctor.overall));
    lines
}

fn doctor_lines_plain(doctor: &DoctorResponse) -> Vec<String> {
    let mut lines: Vec<String> = doctor
        .checks
        .iter()
        .map(|check| match &check.message {
            Some(msg) => format!("{}\t{}\t{msg}", check.name, check.status),
            None => format!("{}\t{}", check.name, check.status),
        })
        .collect();
    lines.push(format!("overall\t{}", doctor.overall));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_companion_client::dto::DoctorCheck;

    fn sample_doctor(overall: &str) -> DoctorResponse {
        DoctorResponse {
            checks: vec![
                DoctorCheck {
                    name: "vault_state".to_owned(),
                    status: "pass".to_owned(),
                    message: Some("unsealed".to_owned()),
                    duration_ms: 0,
                },
                DoctorCheck {
                    name: "audit_chain_integrity".to_owned(),
                    status: "pass".to_owned(),
                    message: None,
                    duration_ms: 4,
                },
            ],
            overall: overall.to_owned(),
        }
    }

    #[test]
    fn doctor_human_lines_include_checks_and_overall() {
        let lines = doctor_lines_human(&sample_doctor("healthy"));
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("vault_state"));
        assert!(lines[0].contains("pass"));
        assert!(lines[0].contains("unsealed"));
        assert!(lines[1].starts_with("audit_chain_integrity"));
        assert!(lines[2].starts_with("overall"));
        assert!(lines[2].ends_with("healthy"));
    }

    #[test]
    fn doctor_plain_lines_are_tab_separated() {
        let lines = doctor_lines_plain(&sample_doctor("unhealthy"));
        assert_eq!(lines[0], "vault_state\tpass\tunsealed");
        assert_eq!(lines[1], "audit_chain_integrity\tpass");
        assert_eq!(lines[2], "overall\tunhealthy");
    }

    #[test]
    fn doctor_name_width_accounts_for_overall() {
        let doctor = DoctorResponse {
            checks: vec![DoctorCheck {
                name: "ok".to_owned(),
                status: "pass".to_owned(),
                message: None,
                duration_ms: 0,
            }],
            overall: "healthy".to_owned(),
        };
        assert_eq!(doctor_name_width(&doctor), "overall".len());
    }

    #[test]
    fn format_bytes_uses_binary_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        // 233696 / 1024 ≈ 228.2 → rounds to whole KB when ≥ 100
        assert_eq!(format_bytes(233_696), "228 KB");
        // ~2.18 TiB (2401308147712 / 1024^4)
        let s = format_bytes(2_401_308_147_712);
        assert_eq!(s, "2.18 TB");
    }

    #[test]
    fn human_field_bytes_keys_are_pretty() {
        let rendered = render_human_field("db_size_bytes", &serde_json::json!(233_696));
        assert_eq!(rendered, "228 KB");
        let free =
            render_human_field("disk_free_bytes", &serde_json::json!(2_401_308_147_712_u64));
        assert_eq!(free, "2.18 TB");
    }

    #[test]
    fn human_field_warnings_are_plain_text() {
        let one = render_human_field(
            "warnings",
            &serde_json::json!(["keychain probe timed out"]),
        );
        assert_eq!(one, "keychain probe timed out");
        assert_eq!(
            render_human_field("warnings", &serde_json::json!([])),
            "(none)"
        );
    }

    #[test]
    fn plain_mode_keeps_raw_byte_integers() {
        // Plain/scripts must not get "228.2 KB" — only Human is pretty.
        assert_eq!(render_scalar(&serde_json::json!(233_696)), "233696");
    }
}
