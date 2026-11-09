//! The calendar, for the periods a data cap resets on.
//!
//! No date library, for the same reason there is no `serde`: the only thing the
//! engine needs is "which UTC day is it" and "which UTC month is it", and both
//! are integer arithmetic on the Unix timestamp it already receives.
//!
//! Everything here is **UTC**. Local time would need a timezone database or a
//! call into the OS (and therefore `unsafe` or a dependency), and a cap that
//! resets at 00:00 UTC is a far smaller surprise than one that resets at an
//! hour nobody can predict. `docs/CONFIG.md` says so where the cap is
//! documented.
//!
//! The month computation is Howard Hinnant's `civil_from_days`, which is exact
//! for every date in the proleptic Gregorian calendar and uses no lookup tables.

/// Days since the Unix epoch, plus the month that day belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Calendar {
    /// Days since 1970-01-01 (UTC).
    pub day: u32,
    /// Months since 1970-01: `(year - 1970) * 12 + (month - 1)`.
    pub month: u32,
}

/// Seconds in a day.
pub const SECS_PER_DAY: u64 = 86_400;

impl Calendar {
    /// Calendar position of a Unix timestamp in seconds.
    ///
    /// Negative timestamps (before 1970) are clamped to the epoch: a data cap
    /// on a machine whose clock is that wrong has larger problems.
    #[must_use]
    pub const fn from_unix_secs(secs: u64) -> Self {
        Self::from_day_index((secs / SECS_PER_DAY) as u32)
    }

    /// Calendar position of a day index.
    #[must_use]
    pub const fn from_day_index(day: u32) -> Self {
        Self {
            day,
            month: month_index(day),
        }
    }

    /// Which period stamp applies to `period`.
    #[must_use]
    pub const fn stamp(self, period: crate::config::CapPeriod) -> u32 {
        match period {
            crate::config::CapPeriod::Day => self.day,
            crate::config::CapPeriod::Month => self.month,
        }
    }

    /// Does `stamp`, recorded under `period`, still cover `self`?
    ///
    /// A stamp from the future (the clock moved backwards) is treated as stale
    /// as well: keeping a counter that nobody can explain is worse than
    /// restarting it.
    #[must_use]
    pub const fn covers(self, period: crate::config::CapPeriod, stamp: u32) -> bool {
        stamp == self.stamp(period)
    }
}

/// `(year - 1970) * 12 + (month - 1)` for a day index, Gregorian, UTC.
#[must_use]
pub const fn month_index(day: u32) -> u32 {
    let (y, m) = civil_from_days(day as i64);
    ((y - 1970) * 12 + (m - 1)) as u32
}

/// Year and month for a day index. The day of the month is not returned: a cap
/// period never needs it.
///
/// Howard Hinnant's `civil_from_days`: shift the epoch to 0000-03-01 so that
/// leap days land at the end of the year, then divide by the 400-year era.
#[must_use]
pub const fn civil_from_days(days: i64) -> (i64, i64) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11], March = 0
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CapPeriod;

    /// Day indices computed independently (`datetime.date(...) - 1970-01-01`).
    const CASES: [(u32, i64, i64); 6] = [
        (0, 1970, 1),
        (10_956, 1999, 12),
        (11_016, 2000, 2),  // leap day
        (19_783, 2024, 3),  // leap year, after February
        (20_766, 2026, 11), // the day this was written
        (47_541, 2100, 3),  // 2100 is not a leap year
    ];

    #[test]
    fn decodes_known_dates() {
        for (day, year, month) in CASES {
            assert_eq!(
                civil_from_days(i64::from(day)),
                (year, month),
                "day {day} should be {year}-{month:02}"
            );
            assert_eq!(
                month_index(day),
                ((year - 1970) * 12 + (month - 1)) as u32,
                "month index for day {day}"
            );
        }
    }

    #[test]
    fn unix_seconds_land_on_the_right_day() {
        assert_eq!(Calendar::from_unix_secs(0), Calendar::from_day_index(0));
        // One second before midnight is still the previous day.
        assert_eq!(Calendar::from_unix_secs(SECS_PER_DAY - 1).day, 0);
        assert_eq!(Calendar::from_unix_secs(SECS_PER_DAY).day, 1);
        let noon = 20_766 * SECS_PER_DAY + 12 * 3600;
        assert_eq!(Calendar::from_unix_secs(noon).day, 20_766);
        assert_eq!(Calendar::from_unix_secs(noon).month, 682);
    }

    #[test]
    fn period_stamps_roll_over_independently() {
        let first = Calendar::from_day_index(0);
        let same_month_next_day = Calendar::from_day_index(1);
        let next_month = Calendar::from_day_index(31);

        assert!(same_month_next_day.covers(CapPeriod::Month, first.month));
        assert!(!same_month_next_day.covers(CapPeriod::Day, first.day));

        assert!(!next_month.covers(CapPeriod::Month, first.month));
        assert!(!next_month.covers(CapPeriod::Day, first.day));
    }

    #[test]
    fn a_stamp_from_the_future_is_stale() {
        // The clock was wrong, or went backwards; either way the counter is not
        // trustworthy, so it must not be treated as current.
        let now = Calendar::from_day_index(100);
        assert!(!now.covers(CapPeriod::Day, 101));
        assert!(!now.covers(CapPeriod::Month, now.month + 1));
    }
}
