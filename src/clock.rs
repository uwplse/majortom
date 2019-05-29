use libc::timespec;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Clock {
    sec: u64,
    nsec: u64
}

impl Clock {
    pub fn new() -> Self {
        Self {
            sec: 0,
            nsec: 0
        }
    }
    
    pub fn from_timespec(t: &timespec) -> Self {
        Self {
            sec: t.tv_sec as u64,
            nsec: t.tv_nsec as u64
        }
    }

    pub fn to_timespec(&self) -> timespec {
        timespec {
            tv_sec: self.sec as i64,
            tv_nsec: self.nsec as i64
        }
    }
    
    fn le(&self, other: &Self) -> bool {
        self.sec < other.sec || (self.sec == other.sec && self.nsec <= other.nsec)
    }

    fn normalize(&mut self) {
        if self.nsec >= 1_000_000_000 {
            self.sec += self.nsec / 1_000_000_000;
            self.nsec = self.nsec % 1_000_000_000;
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
