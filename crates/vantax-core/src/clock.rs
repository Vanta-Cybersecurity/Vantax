//! UTC time helpers: Unix seconds, calendar dates and RFC 3339.
//!
//! Kept dependency-free on purpose. Quota resets, audit timestamps, vault
//! time-locks and expiry checks all go through here, and every one of them
//! is computed from the clock at the moment of use.

use crate::VantaxError;
use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day.
pub const SECS_PER_DAY: u64 = 86_400;

/// Current Unix time in seconds (UTC). Returns 0 if the system clock is set
/// before 1970.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
pub fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Proleptic Gregorian date `(year, month, day)` for days since 1970-01-01.
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The UTC calendar date of a Unix timestamp.
pub fn date_of(secs: u64) -> (i64, u32, u32) {
    civil_from_days((secs / SECS_PER_DAY) as i64)
}

/// `YYYY-MM` for a Unix timestamp. Monthly API quotas are keyed by this.
pub fn month_key(secs: u64) -> String {
    let (y, m, _) = date_of(secs);
    format!("{y:04}-{m:02}")
}

/// Unix time of 00:00:00 UTC on the first day of the next month.
pub fn start_of_next_month(secs: u64) -> u64 {
    let (y, m, _) = date_of(secs);
    let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
    (days_from_civil(ny, nm, 1).max(0) as u64) * SECS_PER_DAY
}

/// Unix time of the next 00:00:00 UTC.
pub fn start_of_next_day(secs: u64) -> u64 {
    (secs / SECS_PER_DAY + 1) * SECS_PER_DAY
}

/// Format a Unix timestamp as RFC 3339 in UTC, e.g. `2026-10-15T14:03:00Z`.
pub fn format_rfc3339(secs: u64) -> String {
    let (y, mo, d) = date_of(secs);
    let rem = secs % SECS_PER_DAY;
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

fn digits(s: &str, what: &str) -> Result<u32, VantaxError> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(VantaxError::InvalidInput(format!(
            "bad {what} in timestamp"
        )));
    }
    s.parse()
        .map_err(|_| VantaxError::InvalidInput(format!("bad {what} in timestamp")))
}

/// Parse a timestamp given as Unix seconds (`1767225600`), a UTC date
/// (`2027-01-01`) or RFC 3339 (`2027-01-01T00:00:00Z`, offsets like `+01:00`
/// accepted, fractional seconds ignored).
pub fn parse_timestamp(input: &str) -> Result<u64, VantaxError> {
    let s = input.trim();
    if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) {
        return s
            .parse()
            .map_err(|_| VantaxError::InvalidInput("timestamp out of range".into()));
    }
    let bad = || {
        VantaxError::InvalidInput(format!(
            "expected Unix seconds, YYYY-MM-DD or RFC 3339, got {input:?}"
        ))
    };
    if s.len() < 10 || !s.is_char_boundary(10) {
        return Err(bad());
    }
    let (date, rest) = s.split_at(10);
    let mut parts = date.split('-');
    let (y, m, d) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(y), Some(m), Some(d), None) if y.len() == 4 && m.len() == 2 && d.len() == 2 => (
            i64::from(digits(y, "year")?),
            digits(m, "month")?,
            digits(d, "day")?,
        ),
        _ => return Err(bad()),
    };
    if !(1..=12).contains(&m) || d == 0 || d > days_in_month(y, m) || y < 1970 {
        return Err(bad());
    }
    let mut secs = days_from_civil(y, m, d) * SECS_PER_DAY as i64;
    if !rest.is_empty() {
        let rest = rest
            .strip_prefix('T')
            .or_else(|| rest.strip_prefix('t'))
            .or_else(|| rest.strip_prefix(' '))
            .ok_or_else(bad)?;
        if rest.len() < 8 || !rest.is_char_boundary(8) {
            return Err(bad());
        }
        let (time, mut zone) = rest.split_at(8);
        let t: Vec<&str> = time.split(':').collect();
        if t.len() != 3 {
            return Err(bad());
        }
        let (hh, mm, ss) = (
            digits(t[0], "hour")?,
            digits(t[1], "minute")?,
            digits(t[2], "second")?,
        );
        if hh > 23 || mm > 59 || ss > 60 {
            return Err(bad());
        }
        secs += i64::from(hh * 3600 + mm * 60 + ss);
        if let Some(frac) = zone.strip_prefix('.') {
            let end = frac
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(frac.len());
            if end == 0 {
                return Err(bad());
            }
            zone = &frac[end..];
        }
        match zone {
            "Z" | "z" => {}
            z if z.len() == 6 && (z.starts_with('+') || z.starts_with('-')) && &z[3..4] == ":" => {
                let oh = i64::from(digits(&z[1..3], "offset")?);
                let om = i64::from(digits(&z[4..6], "offset")?);
                if oh > 23 || om > 59 {
                    return Err(bad());
                }
                let offset = oh * 3600 + om * 60;
                secs -= if z.starts_with('+') { offset } else { -offset };
            }
            _ => return Err(bad()),
        }
    }
    u64::try_from(secs).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_known_instants() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }

    #[test]
    fn calendar_round_trip() {
        for days in (-1_000_000i64..1_000_000).step_by(997) {
            let (y, m, d) = civil_from_days(days);
            assert_eq!(days_from_civil(y, m, d), days);
        }
    }

    #[test]
    fn month_boundaries() {
        let dec = parse_timestamp("2026-12-31T23:59:59Z").unwrap();
        assert_eq!(month_key(dec), "2026-12");
        assert_eq!(
            format_rfc3339(start_of_next_month(dec)),
            "2027-01-01T00:00:00Z"
        );
        let feb = parse_timestamp("2028-02-10").unwrap();
        assert_eq!(
            format_rfc3339(start_of_next_month(feb)),
            "2028-03-01T00:00:00Z"
        );
        assert_eq!(
            format_rfc3339(start_of_next_day(dec)),
            "2027-01-01T00:00:00Z"
        );
    }

    #[test]
    fn parse_forms() {
        assert_eq!(parse_timestamp("1767225600").unwrap(), 1_767_225_600);
        assert_eq!(parse_timestamp("2026-01-01").unwrap(), 1_767_225_600);
        assert_eq!(
            parse_timestamp("2026-01-01T00:00:00Z").unwrap(),
            1_767_225_600
        );
        assert_eq!(
            parse_timestamp("2026-01-01T01:00:00+01:00").unwrap(),
            1_767_225_600
        );
        assert_eq!(
            parse_timestamp("2025-12-31T23:00:00.250-01:00").unwrap(),
            1_767_225_600
        );
        for bad in [
            "",
            "2026-13-01",
            "2026-02-30",
            "2026-01-01T25:00:00Z",
            "yesterday",
            "2026-01-01T00:00:00",
        ] {
            assert!(parse_timestamp(bad).is_err(), "{bad} should not parse");
        }
    }
}
