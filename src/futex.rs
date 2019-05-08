#![allow(dead_code)]

/*
The rust standard library doesn't export a bunch of futex symbols from
<linux/futex.h>, so we define them here. This isn't going to be even a little
bit portable.
*/

static FUTEX_WAIT: i32 = 0;
static FUTEX_WAKE: i32 = 1;
static FUTEX_FD: i32 = 2;
static FUTEX_REQUEUE: i32 = 3;
static FUTEX_CMP_REQUEUE: i32 = 4;
static FUTEX_WAKE_OP: i32 = 5;
static FUTEX_LOCK_PI: i32 = 6;
static FUTEX_UNLOCK_PI: i32 = 7;
static FUTEX_TRYLOCK_PI: i32	= 8;
static FUTEX_WAIT_BITSET: i32 = 9;
static FUTEX_WAKE_BITSET: i32 = 10;
static FUTEX_WAIT_REQUEUE_PI: i32 = 11;
static FUTEX_CMP_REQUEUE_PI: i32 = 12;
    
static FUTEX_PRIVATE_FLAG: i32 = 128;
static FUTEX_CLOCK_REALTIME: i32 = 256;
static FUTEX_CMD_MASK: i32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

#[derive(Debug)]
pub enum FutexCmd {
    Wait, Wake, WaitBitset
}

#[derive(Debug)]
pub struct Futex {
    pub cmd: FutexCmd, pub private: bool, pub realtime: bool
}

impl Futex {
    pub fn from_i32(op: i32) -> Option<Futex> {
        let raw_cmd = op & FUTEX_CMD_MASK;
        let cmd = match raw_cmd {
            x if x == FUTEX_WAIT => Some(FutexCmd::Wait),
            x if x == FUTEX_WAKE => Some(FutexCmd::Wake),
            x if x == FUTEX_WAIT_BITSET => Some(FutexCmd::WaitBitset),
            _ => None
        };
        let private = (op & FUTEX_PRIVATE_FLAG) != 0;
        let realtime = (op & FUTEX_CLOCK_REALTIME) != 0;
        if let Some(cmd) = cmd {
            Some(Futex {cmd, private, realtime})
        } else {
            None
        }
    }
}
