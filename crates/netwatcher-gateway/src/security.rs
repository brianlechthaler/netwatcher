use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    max_per_window: u32,
    window: Duration,
    state: Mutex<(Instant, u32)>,
}

impl RateLimiter {
    pub fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            max_per_window,
            window,
            state: Mutex::new((Instant::now(), 0)),
        }
    }

    pub fn check(&self) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return false;
        };
        let (window_start, count) = &mut *guard;
        if window_start.elapsed() >= self.window {
            *window_start = Instant::now();
            *count = 0;
        }
        if *count >= self.max_per_window {
            return false;
        }
        *count += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limiter_blocks_after_threshold() {
        let limiter = RateLimiter::new(2, Duration::from_secs(60));
        assert!(limiter.check());
        assert!(limiter.check());
        assert!(!limiter.check());
    }
}
