use libc::{timespec, timeval};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Clock {
    sec: u64,
    nsec: u64,
}

impl fmt::Display for Clock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.sec, self.nsec)
    }
}

impl Clock {
    pub fn new() -> Self {
        Self { sec: 0, nsec: 0 }
    }

    pub fn from_timespec(t: &timespec) -> Self {
        Self {
            sec: t.tv_sec as u64,
            nsec: t.tv_nsec as u64,
        }
    }

    pub fn from_millis(ms: u32) -> Self {
        let mut c = Self {
            sec: (ms / 1000).into(),
            nsec: ((ms % 1000) * 1_000_000).into(),
        };
        c.normalize();
        c
    }

    pub fn to_timeval(&self) -> timeval {
        #[cfg(target_os = "linux")]
        return timeval {
            tv_sec: self.sec as i64,
            tv_usec: (self.nsec / 1000) as i64,
        };
        #[cfg(not(target_os = "linux"))]
        return timeval {
            tv_sec: self.sec as i64,
            tv_usec: (self.nsec / 1000) as i32,
        };
    }

    pub fn to_timespec(&self) -> timespec {
        timespec {
            tv_sec: self.sec as i64,
            tv_nsec: self.nsec as i64,
        }
    }

    fn le(&self, other: &Self) -> bool {
        self.sec < other.sec || (self.sec == other.sec && self.nsec <= other.nsec)
    }

    fn normalize(&mut self) {
        if self.nsec >= 1_000_000_000 {
            self.sec += self.nsec / 1_000_000_000;
            self.nsec %= 1_000_000_000;
        }
    }

    pub fn advance(&mut self, other: &Self) {
        self.sec += other.sec;
        self.nsec += other.nsec;
        self.normalize();
    }

    pub fn ensure_gt(&mut self, other: &Self) {
        if self.le(other) {
            self.sec = other.sec;
            self.nsec = other.nsec + 1;
            self.normalize();
        }
    }
}
