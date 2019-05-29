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

// FUTEX_WAKE_OP stuff

static FUTEX_OP_SET: i32 = 0;  /* uaddr2 = oparg; */
static FUTEX_OP_ADD: i32 = 1;  /* uaddr2 += oparg; */
static FUTEX_OP_OR: i32 = 2;  /* uaddr2 |= oparg; */
static FUTEX_OP_ANDN: i32 = 3;  /* uaddr2 &= ~oparg; */
static FUTEX_OP_XOR: i32 = 4;  /* uaddr2 ^= oparg; */

static FUTEX_OP_ARG_SHIFT: i32 = 8;  /* Use (1 << oparg) as operand */

static FUTEX_OP_CMP_EQ: i32 = 0;  /* if (oldval == cmparg) wake */
static FUTEX_OP_CMP_NE: i32 = 1;  /* if (oldval != cmparg) wake */
static FUTEX_OP_CMP_LT: i32 = 2;  /* if (oldval < cmparg) wake */
static FUTEX_OP_CMP_LE: i32 = 3;  /* if (oldval <= cmparg) wake */
static FUTEX_OP_CMP_GT: i32 = 4;  /* if (oldval > cmparg) wake */
static FUTEX_OP_CMP_GE: i32 = 5;  /* if (oldval >= cmparg) wake */

pub static FUTEX_BITSET_MATCH_ANY: u32 = 0xffffffff;


#[derive(Debug)]
pub enum FutexCmd {
    Wait, Wake, WaitBitset, WakeBitset, CmpRequeue, WakeOp
}

#[derive(Debug)]
pub struct Futex {
    pub cmd: FutexCmd, pub private: bool, pub realtime: bool
}

#[derive(Debug, PartialEq, Clone)]
pub enum FutexWakeOp {
    Set, Add, Or, AndN, Xor
}

#[derive(Debug, PartialEq, Clone)]
pub enum FutexWakeCmp {
    Eq, Ne, Lt, Le, Gt, Ge
}

#[derive(Debug, PartialEq, Clone)]
pub struct FutexWakeOpArgs {
    pub op: FutexWakeOp,
    pub oparg: i32,
    pub cmp: FutexWakeCmp,
    pub cmparg: i32
}

impl Futex {
    pub fn from_i32(op: i32) -> Option<Futex> {
        let raw_cmd = op & FUTEX_CMD_MASK;
        let cmd = match raw_cmd {
            x if x == FUTEX_WAIT => Some(FutexCmd::Wait),
            x if x == FUTEX_WAKE => Some(FutexCmd::Wake),
            x if x == FUTEX_WAIT_BITSET => Some(FutexCmd::WaitBitset),
            x if x == FUTEX_WAKE_BITSET => Some(FutexCmd::WakeBitset),
            x if x == FUTEX_CMP_REQUEUE => Some(FutexCmd::CmpRequeue),
            x if x == FUTEX_WAKE_OP => Some(FutexCmd::WakeOp),
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

impl FutexWakeOpArgs {
    pub fn from_i32(bits: i32) -> Option<FutexWakeOpArgs> {
        let raw_op_and_shift = (bits >> 28) & 0xf;
        let shift = raw_op_and_shift & FUTEX_OP_ARG_SHIFT != 0;
        let raw_op = raw_op_and_shift & !FUTEX_OP_ARG_SHIFT;
        let raw_cmp = (bits >> 24) & 0xf;
        let mut oparg = (bits >> 12) & 0xfff;
        if shift {
            oparg = 1 << oparg;
        }
        let cmparg = bits & 0xfff;
        use FutexWakeOp::*;
        use FutexWakeCmp::*;
        let op = match raw_op {
            x if x == FUTEX_OP_SET => Set,
            x if x == FUTEX_OP_ADD => Add,
            x if x == FUTEX_OP_OR => Or,
            x if x == FUTEX_OP_ANDN => AndN,
            x if x == FUTEX_OP_XOR => Xor,
            _ => return None
        };
        let cmp = match raw_cmp {
            x if x == FUTEX_OP_CMP_EQ => Eq,
            x if x == FUTEX_OP_CMP_NE => Ne,
            x if x == FUTEX_OP_CMP_LT => Lt,
            x if x == FUTEX_OP_CMP_LE => Le,
            x if x == FUTEX_OP_CMP_GT => Gt,
            x if x == FUTEX_OP_CMP_GE => Ge,
            _ => return None
        };
        Some(FutexWakeOpArgs {
            op, oparg, cmp, cmparg
        })
    }
}

#[test]
fn test_futex_wake_op() {
    // translated from the FUTEX_OP macro in the futex man page
    fn encode(op: i32, cmp: i32, oparg: i32, cmparg: i32) -> i32 {
        ((op & 0xf) << 28)  |
        ((cmp & 0xf) << 24) |
        ((oparg & 0xfff) << 12) |
        (cmparg & 0xfff)
    }

    assert_eq!(FutexWakeOpArgs::from_i32(encode(FUTEX_OP_SET,
                                                FUTEX_OP_CMP_EQ,
                                                42,
                                                47)),
               Some(FutexWakeOpArgs {
                   op: FutexWakeOp::Set,
                   cmp: FutexWakeCmp::Eq,
                   oparg: 42,
                   cmparg: 47
               }));

    assert_eq!(FutexWakeOpArgs::from_i32(encode(FUTEX_OP_SET | FUTEX_OP_ARG_SHIFT,
                                                FUTEX_OP_CMP_EQ,
                                                2,
                                                47)),
               Some(FutexWakeOpArgs {
                   op: FutexWakeOp::Set,
                   cmp: FutexWakeCmp::Eq,
                   oparg: 4,
                   cmparg: 47
               }));
}
