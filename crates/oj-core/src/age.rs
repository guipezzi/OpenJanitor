//! Parsing and describing file ages ("24h", "7d").

use std::time::Duration;

/// The minimum age used when neither the rule nor the user sets one.
pub const DEFAULT_MIN_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid age {0:?}: use a whole number followed by m, h, or d (for example \"24h\")")]
pub struct AgeError(String);

/// Parses `"30m"`, `"24h"`, `"7d"`, or `"0"`.
pub fn parse_age(text: &str) -> Result<Duration, AgeError> {
    let error = || AgeError(text.to_string());
    let trimmed = text.trim();
    if trimmed == "0" {
        return Ok(Duration::ZERO);
    }
    let unit_start = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(error)?;
    let (number, unit) = trimmed.split_at(unit_start);
    let number: u64 = number.parse().map_err(|_| error())?;
    let seconds_per_unit = match unit {
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        _ => return Err(error()),
    };
    number
        .checked_mul(seconds_per_unit)
        .map(Duration::from_secs)
        .ok_or_else(error)
}

/// "3 days", "5 hours", "12 minutes".
pub fn describe(age: Duration) -> String {
    let minutes = age.as_secs() / 60;
    let (value, unit) = match minutes {
        m if m >= 24 * 60 => (m / (24 * 60), "day"),
        m if m >= 60 => (m / 60, "hour"),
        m => (m, "minute"),
    };
    let plural = if value == 1 { "" } else { "s" };
    format!("{value} {unit}{plural}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ages() {
        assert_eq!(parse_age("0"), Ok(Duration::ZERO));
        assert_eq!(parse_age("30m"), Ok(Duration::from_secs(1800)));
        assert_eq!(parse_age("24h"), Ok(DEFAULT_MIN_AGE));
        assert_eq!(parse_age("7d"), Ok(Duration::from_secs(7 * 86400)));
    }

    #[test]
    fn rejects_bad_ages() {
        for text in [
            "",
            "h",
            "24",
            "24x",
            "1.5h",
            "-1d",
            "24 h",
            "99999999999999999999d",
        ] {
            assert!(parse_age(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn describes_ages() {
        assert_eq!(describe(Duration::from_secs(90)), "1 minute");
        assert_eq!(describe(Duration::from_secs(3 * 3600)), "3 hours");
        assert_eq!(describe(Duration::from_secs(86400)), "1 day");
        assert_eq!(describe(Duration::from_secs(10 * 86400)), "10 days");
    }
}
