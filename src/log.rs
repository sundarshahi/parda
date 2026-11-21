//! The evidence log: one JSON line per request in `~/.parda/log.jsonl`. It records what kinds of data
//! were masked and how often — never the values. Rotated at 10 MB, one old file kept.

use crate::vault::Counts;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_BYTES: u64 = 10 << 20;

pub struct Record<'a> {
    pub api: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub masked: &'a Counts,
    pub restored: u64,
    pub mask_us: u64,
}

pub fn append(home: &Path, r: &Record) {
    let file = home.join("log.jsonl");
    if fs::metadata(&file).is_ok_and(|m| m.len() > MAX_BYTES) {
        fs::rename(&file, home.join("log.jsonl.1")).ok();
    }
    let line = serde_json::json!({
        "time": now_iso(),
        "api": r.api,
        "method": r.method,
        "path": r.path,
        "status": r.status,
        "masked": r.masked,
        "restored": r.restored,
        "mask_us": r.mask_us,
    });
    let open = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new().create(true).append(true).mode(0o600).open(&file)
    };
    if let Ok(mut f) = open {
        f.write_all(format!("{line}\n").as_bytes()).ok();
    }
}

/// Totals for log lines whose time starts with `day` (`YYYY-MM-DD`): requests, and counts per kind.
pub fn summary(home: &Path, day: &str) -> (u64, BTreeMap<String, u64>) {
    let mut requests = 0;
    let mut kinds = BTreeMap::new();
    let text = fs::read_to_string(home.join("log.jsonl")).unwrap_or_default();
    for v in text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()) {
        if !v["time"].as_str().is_some_and(|t| t.starts_with(day)) {
            continue;
        }
        requests += 1;
        if let Some(m) = v["masked"].as_object() {
            for (k, n) in m {
                *kinds.entry(k.clone()).or_default() += n.as_u64().unwrap_or(0);
            }
        }
    }
    (requests, kinds)
}

pub fn now_iso() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    iso(secs)
}

/// UTC `YYYY-MM-DDTHH:MM:SSZ` (Howard Hinnant's days-to-civil).
fn iso(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_dates() {
        assert_eq!(iso(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso(1_795_219_200), "2026-11-21T00:00:00Z");
        assert_eq!(iso(951_782_400 + 3_661), "2000-02-29T01:01:01Z");
    }
}
