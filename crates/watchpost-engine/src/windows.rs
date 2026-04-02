use chrono::{DateTime, Utc};

/// Immediate time window: events within a fixed duration of the trigger
/// receive full weight; events outside get zero.
pub struct ImmediateWindow {
    pub duration_ms: u64,
}

impl ImmediateWindow {
    pub fn new(duration_ms: u64) -> Self {
        Self { duration_ms }
    }

    /// Returns `1.0` if `event_time` falls within the window after
    /// `trigger_time`, `0.0` otherwise.
    pub fn temporal_weight(
        &self,
        trigger_time: DateTime<Utc>,
        event_time: DateTime<Utc>,
    ) -> f64 {
        let elapsed = event_time
            .signed_duration_since(trigger_time)
            .num_milliseconds();
        if elapsed >= 0 && (elapsed as u64) <= self.duration_ms {
            1.0
        } else {
            0.0
        }
    }
}

impl Default for ImmediateWindow {
    fn default() -> Self {
        Self::new(5000)
    }
}

/// Session window: weight decays over the estimated session duration while the
/// trigger session is active; returns `0.0` when inactive.
pub struct SessionWindow;

impl SessionWindow {
    /// Estimated session duration in seconds for decay calculation.
    const ESTIMATED_SESSION_SECS: f64 = 300.0;

    /// Compute the temporal weight for a session-scoped event.
    ///
    /// While the trigger is active the weight is `0.7 - 0.4 * elapsed_fraction`
    /// clamped to `[0.3, 0.7]`. When the trigger is inactive the weight is `0.0`.
    pub fn temporal_weight(
        trigger_start: DateTime<Utc>,
        trigger_active: bool,
        event_time: DateTime<Utc>,
    ) -> f64 {
        if !trigger_active {
            return 0.0;
        }

        let elapsed_secs = event_time
            .signed_duration_since(trigger_start)
            .num_milliseconds() as f64
            / 1000.0;
        let elapsed_fraction = elapsed_secs / Self::ESTIMATED_SESSION_SECS;
        let weight = 0.7 - (0.4 * elapsed_fraction);
        weight.clamp(0.3, 0.7)
    }
}

/// Persistent window: weak correlation for events that occur hours after
/// a trigger. Uses a constant weight of 0.1 for any event that matches
/// a persistent trigger within the configured time horizon (default 24h).
///
/// This catches delayed-execution attacks where a package plants a cron job
/// during install and the payload fires hours later.
pub struct PersistentWindow {
    pub max_age_hours: u64,
}

impl PersistentWindow {
    pub fn new(max_age_hours: u64) -> Self {
        Self { max_age_hours }
    }

    /// Returns 0.1 (constant weak signal) if the event falls within the
    /// persistent window, 0.0 otherwise.
    pub fn temporal_weight(
        &self,
        trigger_time: DateTime<Utc>,
        event_time: DateTime<Utc>,
    ) -> f64 {
        let elapsed_hours = event_time
            .signed_duration_since(trigger_time)
            .num_hours();
        if elapsed_hours >= 0 && (elapsed_hours as u64) <= self.max_age_hours {
            0.1
        } else {
            0.0
        }
    }
}

impl Default for PersistentWindow {
    fn default() -> Self {
        Self::new(24)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn immediate_window_within() {
        let w = ImmediateWindow::new(5000);
        let trigger = Utc::now();
        let event = trigger + Duration::seconds(2);
        assert_eq!(w.temporal_weight(trigger, event), 1.0);
    }

    #[test]
    fn immediate_window_beyond() {
        let w = ImmediateWindow::new(5000);
        let trigger = Utc::now();
        let event = trigger + Duration::seconds(6);
        assert_eq!(w.temporal_weight(trigger, event), 0.0);
    }

    #[test]
    fn session_window_active_early() {
        let trigger = Utc::now();
        let event = trigger + Duration::seconds(10);
        let weight = SessionWindow::temporal_weight(trigger, true, event);
        // 10s / 300s = 0.033..., weight ≈ 0.7 - 0.4*0.033 ≈ 0.687
        assert!(weight >= 0.3 && weight <= 0.7, "weight was {}", weight);
    }

    #[test]
    fn session_window_inactive() {
        let trigger = Utc::now();
        let event = trigger + Duration::seconds(10);
        let weight = SessionWindow::temporal_weight(trigger, false, event);
        assert_eq!(weight, 0.0);
    }

    #[test]
    fn persistent_window_within_24h() {
        let w = PersistentWindow::new(24);
        let trigger = Utc::now();
        let event = trigger + Duration::hours(6);
        assert_eq!(w.temporal_weight(trigger, event), 0.1);
    }

    #[test]
    fn persistent_window_beyond_24h() {
        let w = PersistentWindow::new(24);
        let trigger = Utc::now();
        let event = trigger + Duration::hours(25);
        assert_eq!(w.temporal_weight(trigger, event), 0.0);
    }
}
