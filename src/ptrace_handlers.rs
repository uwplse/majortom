#![allow(dead_code)]
#![allow(unused_imports)]

use crate::clock::Clock;
use crate::config::Config;
use crate::futex::{
    Futex, FutexCmd, FutexWakeCmp, FutexWakeOp, FutexWakeOpArgs, FUTEX_BITSET_MATCH_ANY,
};
use base64_serde::base64_serde_type;
use failure::Error;
use failure::ResultExt;
#[cfg(target_os = "linux")]
use libc::{epoll_event, user_regs_struct};
use nix::fcntl::OFlag;
#[cfg(target_os = "linux")]
use nix::sched::CloneFlags;
#[cfg(target_os = "linux")]
use nix::sys::epoll::{EpollFlags, EpollOp};
use nix::sys::ptrace;
use nix::sys::socket::{
    sockaddr_in, sockaddr_storage, AddressFamily, MsgFlags, SockFlag, SockProtocol, SockType,
};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use nix::unistd::{execv, fork, ForkResult};
use protojson::ProtobufToJson;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fmt;
use std::io::{BufReader, Read, Write};
use std::mem::size_of;
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;
use std::slice;
use tempfile::TempDir;

base64_serde_type!(Base64Standard, base64::STANDARD);

use crate::data;

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq)]
enum File {
    TcpSocket(Option<SocketAddress>),
    UDPSocket(Option<SocketAddress>),
    EpollFd(
        Vec<(i32, EpollFlags, u64)>,
        Rc<RefCell<Option<(TracedProcessIdentifier, Syscall)>>>,
    ), // fds, waiting
    TimerFd(TimeoutId), // armed, repeating
    SignalFd,
    ReadFile(String),
    Random,
    WriteFile(String),
    Special,
}

#[cfg(target_os = "linux")]
impl File {
    fn is_special(&self) -> bool {
        match self {
            File::Special => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
struct FileSystemSnapshot {
    dir: TempDir,
    files: HashMap<String, Option<String>>,
    files_to_restore: Vec<String>,
    filenumber: i32,
    directories: HashSet<String>,
}

fn is_read_only(flags: i32) -> bool {
    (flags & libc::O_ACCMODE) == libc::O_RDONLY
}

#[derive(Debug)]
struct TcpChannel {
    remote: Option<TcpStream>,
    listener: Option<TcpListener>,
    local: Option<TcpStream>,
    sent: Rc<RefCell<usize>>,
    received: Rc<RefCell<usize>>,
    delivered: Rc<RefCell<usize>>,
    remote_addr: Option<SocketAddress>,
}

impl TcpChannel {
    fn new() -> Self {
        Self {
            remote: None,
            listener: None,
            local: None,
            sent: Rc::new(RefCell::new(0)),
            received: Rc::new(RefCell::new(0)),
            delivered: Rc::new(RefCell::new(0)),
            remote_addr: None,
        }
    }

    fn reverse(&self, addr: SocketAddress) -> Self {
        Self {
            remote: match self.local {
                None => None,
                Some(ref s) => Some(s.try_clone().unwrap()),
            },
            listener: self.listener.as_ref().map(|s| s.try_clone().unwrap()),
            local: self.remote.as_ref().map(|s| s.try_clone().unwrap()),
            sent: self.received.clone(),
            received: self.sent.clone(),
            delivered: Rc::new(RefCell::new(0)),
            remote_addr: Some(addr),
        }
    }

    fn send(&self, len: usize) {
        *self.sent.borrow_mut() += len;
    }
}

/*
impl TcpChannel {
    fn reverse(&self) -> Self {
        Self {remote: self.local.clone(),
              local: self.remote.clone()}
    }
}*/

impl FileSystemSnapshot {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            dir: tempfile::Builder::new().prefix("files").tempdir()?,
            files: HashMap::new(),
            files_to_restore: Vec::new(),
            directories: HashSet::new(),
            filenumber: 0,
        })
    }

    #[allow(clippy::map_entry)]
    fn snapshot_file(&mut self, filename: String) -> Result<(), Error> {
        if !self.files.contains_key(&filename) {
            let name = self.filenumber.to_string();
            self.filenumber += 1;
            let path = self.dir.path().join(name);
            if std::path::Path::new(&filename).exists() {
                std::fs::copy(&filename, &path).expect("couldn't copy file");
                self.files
                    .insert(filename, Some(path.to_str().unwrap().to_owned()));
            } else {
                self.files.insert(filename, None);
            }
        }
        Ok(())
    }

    fn snapshot_directory(&mut self, filename: String) {
        if !self.directories.contains(&filename) {
            self.directories.insert(filename.clone());
        }
    }

    fn mark_for_restoration(&mut self, filename: String) {
        assert!(self.files.contains_key(&filename));
        self.files_to_restore.push(filename);
    }

    fn restore_snapshot(&self) -> Result<(), Error> {
        trace!("Restoring snapshot {:?}", self);
        for directory in self.directories.iter() {
            if std::path::Path::new(&directory).exists() {
                trace!("Deleting directory: {}", directory);
                std::fs::remove_dir_all(directory)?;
            } else {
                trace!(
                    "Directory {} doesn't exist and shouldn't--we're good",
                    directory
                );
            }
        }
        for file in self.files_to_restore.iter() {
            let snapshot = &self.files[&file.clone()];
            trace!("Restoring {} from {:?}", file, snapshot);
            match snapshot {
                Some(snapshot) => {
                    trace!("Copying {} to {}", snapshot, file);
                    std::fs::copy(snapshot, file)?;
                }
                None => {
                    if std::path::Path::new(&file).exists() {
                        trace!("Deleting file: {}", file);
                        std::fs::remove_file(file)?;
                    } else {
                        trace!("{} doesn't exist and shouldn't--we're good", file);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
struct TracedProcess {
    name: String,
    tgid: Pid,
    tid: Pid,
    files: Rc<RefCell<HashMap<i32, File>>>,
    snapshot: Rc<RefCell<FileSystemSnapshot>>,
    counter: Rc<RefCell<u64>>,
    clock: Rc<RefCell<Clock>>,
}

#[cfg(target_os = "linux")]
impl fmt::Display for TracedProcess {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.tgid == self.tid {
            write!(f, "TracedProcess({})", self.tgid)
        } else {
            write!(f, "TracedProcess({}/{})", self.tgid, self.tid)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TracedProcessIdentifier {
    name: String,
    tid: Option<Pid>, // used only for child threads
}

impl TracedProcessIdentifier {
    fn main_process(name: String) -> Self {
        Self { name, tid: None }
    }

    fn child_process(&self, tid: Pid) -> Self {
        Self {
            name: self.name.clone(),
            tid: Some(tid),
        }
    }

    fn parent_process(&self) -> Self {
        Self {
            name: self.name.clone(),
            tid: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct TimeoutId {
    name: String,
    id: u64,
    recurring: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct WireTimeout {
    timeout_id: TimeoutId,
    clock: Clock,
}

impl TimeoutId {
    fn new(name: String, id: u64, recurring: bool) -> Self {
        Self {
            name,
            id,
            recurring,
        }
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
enum MessageData {
    TcpConnect(u64),
    TcpAck(String),
    #[serde(with = "Base64Standard")]
    Data(Vec<u8>),
    TcpMessage(usize),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct WireMessage {
    from: Option<SocketAddress>,
    to: SocketAddress,
    data: MessageData,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Handlers {
    nodes: HashMap<String, String>,
    procs: HashMap<TracedProcessIdentifier, TracedProcess>,
    message_waiting_procs: HashMap<SocketAddress, (TracedProcessIdentifier, Syscall)>,
    timeout_waiting_procs: HashMap<TimeoutId, (TracedProcessIdentifier, Syscall)>,
    address_to_name: HashMap<SocketAddress, String>,
    tcp_channels: HashMap<(String, u64), TcpChannel>,
    current_timeout: HashMap<TracedProcessIdentifier, data::Timeout>,
    current_message: Option<data::Message>,
    current_state: Option<serde_json::Value>,
    annotate_state_procs: HashMap<TracedProcessIdentifier, TracedProcessIdentifier>,
    current_tcp_message: Option<(SocketAddress, usize)>,
    // futex -> waiters (if any)
    futexes: HashMap<u64, VecDeque<(TracedProcessIdentifier, Syscall)>>,
    protobuf_to_json: Option<ProtobufToJson>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum SocketAddress {
    // for now, we only care about the port.
    IPV4(u16),
    IPV6(u16),
    // fake socket address for Tcp streams
    TcpStream(String, u64),
}

#[derive(Debug, Clone, PartialEq)]
enum FcntlCmd {
    GetFl,
    SetFd,        // we don't care about these, really
    SetFl(OFlag), // we do care about these
}

#[derive(Debug, Clone, PartialEq)]
enum TimerCmd {
    Arm(Clock),
    ArmRecurring,
    Disarm,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq)]
enum Syscall {
    Brk,
    MProtect,
    ArchPrctl,
    Access(String),
    // filename, flags
    Open(String, i32),
    Dup(i32),
    Stat,
    Fstat(i32, File),
    MMap(i32, Option<File>),
    Pipe(u64), // address
    MUnmap,
    Close(i32, File),
    Read(i32, File, u64, usize),
    UDPSocket,
    TcpSocket,
    GetAddrInfoSocket,
    SpecialOp,
    Bind(i32, SocketAddress),
    Listen(i32, i32),
    Connect(i32, File, SocketAddress),
    Accept(i32, File),
    Write(i32, File),
    RecvFrom(i32, File, usize, MsgFlags),
    SigProcMask,
    SigAction,
    NanoSleep(TimeoutId, Clock),
    SendTo(i32, File, Option<SocketAddress>, Vec<u8>),
    SendMsg(i32, File),
    SetTidAddress,
    SetRobustList,
    // Futex handling! There's one "Futex" syscall that does many different
    // things, so we have some fake Futex calls to disambiguate.
    FutexTest,
    FutexWait(u64, i32, u32, Option<(TimeoutId, Clock)>),
    FutexWake(u64, usize, u32),
    FutexCmpRequeue(u64, usize, u64, usize),
    FutexWakeOp(u64, usize, u64, usize, FutexWakeOpArgs),
    GetRLimit,
    PRLimit64,
    Clone(CloneFlags),
    SigAltStack,
    SchedSetAffinity,
    SchedGetAffinity,
    LSeek,
    MkDir(String),
    SetSockOpt(i32, i32, i32),
    Uname,
    GetSockName,
    GetPeerName,
    GetPid,
    GetTid,
    SysInfo,
    ReadLink,
    SetITimer,
    GetTime,
    GetTimeOfDay,
    Time,
    IoCtl,
    Fcntl(i32, File, FcntlCmd),
    Unlink(String),
    Symlink(String, String),
    Fsync,
    FDataSync,
    FLock,
    MSync,
    MInCore,
    MAdvise,
    GetDents,
    GetCwd,
    SchedYield,
    TimerFdCreate,
    TimerFdSetTime(File, TimerCmd),
    SignalFd,
    EpollCreate,
    // EpollFlags must be set if op is add or mod
    EpollCtl(i32, EpollOp, i32, Option<EpollFlags>, Option<u64>),
    EpollWait(i32, u64, usize, Option<(TimeoutId, Clock)>),
    Upcall(usize),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SyscallReturn {
    Success(i64),
    Failure(i64),
}

impl SyscallReturn {
    fn is_success(&self) -> bool {
        match self {
            SyscallReturn::Success(_) => true,
            _ => false,
        }
    }
}

#[cfg(target_os = "linux")]
impl TracedProcess {
    fn new(name: String, program: String) -> Result<Self, Error> {
        let args: Vec<&str> = program.split(" ").collect();
        let program_name = args[0];
        let mut files = HashMap::new();
        //stdin, stdout, stderr
        for fd in 0..3 {
            files.insert(fd, File::Special);
        }
        let proc = match fork()? {
            ForkResult::Parent { child, .. } => {
                trace!("Started child with pid {}", child);
                Self {
                    name: name,
                    tgid: child,
                    tid: child,
                    files: Rc::new(RefCell::new(files)),
                    counter: Rc::new(RefCell::new(0)),
                    snapshot: Rc::new(RefCell::new(FileSystemSnapshot::new()?)),
                    clock: Rc::new(RefCell::new(Clock::new())),
                }
            }
            ForkResult::Child => {
                std::env::set_var("LD_PRELOAD", "./novdso.so");
                ptrace::traceme().expect("couldn't call trace");
                let args_cstring: Vec<CString> =
                    args.into_iter().map(|s| CString::new(s).unwrap()).collect();
                execv(&CString::new(program_name).unwrap(), &args_cstring).expect("couldn't exec");
                unreachable!();
            }
        };
        proc.wait_for_process_start()?;
        let options = ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_TRACEVFORK;
        ptrace::setoptions(proc.tid, options)?;
        Ok(proc)
    }

    fn next_counter(&self) -> u64 {
        *self.counter.borrow_mut() += 1;
        *self.counter.borrow()
    }

    fn next_timeout_id(&self) -> TimeoutId {
        let id = self.next_counter();
        TimeoutId::new(self.name.clone(), id, false)
    }

    fn kill(&self, nthreads: usize) -> Result<(), Error> {
        // should only kill group leaders
        assert!(self.tid == self.tgid);
        trace!("Killing process {:?}", self);
        ptrace::kill(self.tid)?;
        for _i in 0..nthreads {
            let status = self.wait_status()?;
            match status {
                WaitStatus::Signaled(_, _, _) => (),
                _ => bail!("Unexpected wait status after killing process: {:?}", status),
            }
        }
        self.snapshot
            .borrow()
            .restore_snapshot()
            .context("Restoring snapshot")?;
        Ok(())
    }

    fn wait_for_process_start(&self) -> Result<(), Error> {
        trace!("waiting for child proc");
        let status = self.wait_status()?;
        match status {
            WaitStatus::Stopped(pid, _) if pid == self.tid => (),
            _ => bail!("Got bad status when waiting for child: {:?}", status),
        };
        Ok(())
    }

    fn wait_status(&self) -> Result<WaitStatus, Error> {
        use nix::sys::signal::Signal;
        loop {
            let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))?;
            match status {
                WaitStatus::Stopped(pid, signal)
                    if (signal == Signal::SIGWINCH || signal == Signal::SIGPROF) =>
                {
                    trace!("Got {}, ignoring it and continuing", signal);
                    // this is a hack!
                    ptrace::syscall(pid)?;
                }
                _ => {
                    return Ok(status);
                }
            }
        }
    }

    fn get_cloned_child(&self) -> Result<(Pid, Self), Error> {
        trace!("Clone executed, getting child info");
        self.run_until_syscall()?;
        let status = self.wait_status()?;
        match status {
            WaitStatus::PtraceEvent(_, _, _) => (),
            _ => bail!("Bad status when trying to get clone info: {:?}", status),
        }
        let child = Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        let proc = Self {
            name: self.name.clone(),
            tgid: self.tgid,
            tid: child,
            files: self.files.clone(),
            counter: Rc::clone(&self.counter),
            snapshot: Rc::clone(&self.snapshot),
            clock: Rc::clone(&self.clock),
        };
        proc.wait_for_process_start()?;
        Ok((child, proc))
    }

    fn wait_on_syscall(&self) -> Result<(), Error> {
        let status = self.wait_status()?;
        if let WaitStatus::PtraceSyscall(p) = status {
            if p != self.tid {
                bail!("Got wait result for wrong process: {:?}", status);
            }
            Ok(())
        } else {
            bail!("Unexpected WaitStatus {:?}", status)
        }
    }

    fn run_until_syscall(&self) -> Result<(), Error> {
        ptrace::syscall(self.tid)?;
        Ok(())
    }

    fn get_registers(&self) -> Result<user_regs_struct, Error> {
        Ok(ptrace::getregs(self.tid)?)
    }

    fn set_registers(&self, regs: user_regs_struct) -> Result<(), Error> {
        Ok(ptrace::setregs(self.tid, regs)?)
    }

    // functions for reading

    fn read_data(&self, addr: u64, len: usize) -> Result<Vec<u8>, Error> {
        let mut buf: [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let mut bytes: Vec<u8> = Vec::with_capacity(len);
        for i in 0..len {
            if i % size_of::<libc::c_long>() == 0 {
                // The use of to_ne_bytes rather than to_be_bytes is a little
                // counter-intuitive. The key is that we're reading a c_long (an
                // i64, that is) from the memory of the target process. We're
                // interested in the underlying bytes, which means that we're
                // interested in the c_long's representation *on this
                // architecture*.
                let raw = ptrace::read(self.tid, (addr + (i as u64)) as ptrace::AddressType)?;
                buf = raw.to_ne_bytes();
                trace!(
                    "Read {:?} ({:?}) from process memory at {:?}",
                    buf,
                    raw,
                    addr
                );
            }
            bytes.push(buf[i % size_of::<libc::c_long>()]);
            // addr incremented once for each *byte* read
        }
        trace!("read bytes {:?}", bytes);
        Ok(bytes)
    }

    fn read_string(&self, addr: u64) -> Result<String, Error> {
        let mut buf: libc::c_long;
        let mut bytes: Vec<u8> = Vec::new();
        let mut addr = addr;
        'outer: loop {
            buf = ptrace::read(self.tid, addr as ptrace::AddressType)?;
            let new_bytes = buf.to_ne_bytes();
            for b in new_bytes.iter() {
                if *b == 0 {
                    break 'outer;
                }
                bytes.push(*b);
                // addr incremented once for each *byte* read
                addr += 1;
            }
        }
        Ok(String::from_utf8(bytes)?)
    }

    unsafe fn read<T>(&self, addr: u64) -> Result<T, Error>
    where
        T: Copy,
    {
        let mut buf: [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let mut bytes: Vec<u8> = Vec::new();
        let total = size_of::<T>();
        for i in 0..total {
            if i % size_of::<libc::c_long>() == 0 {
                buf = ptrace::read(self.tid, (addr + (i as u64)) as ptrace::AddressType)?
                    .to_ne_bytes();
            }
            bytes.push(buf[i % size_of::<libc::c_long>()]);
            // addr incremented once for each *byte* read
        }
        let t_slice = std::mem::transmute::<&[u8], &[T]>(bytes.as_slice());
        Ok(t_slice[0].clone())
    }

    fn read_socket_address(&self, addr: u64, addrlen: usize) -> Result<SocketAddress, Error> {
        unsafe {
            let sas: sockaddr_storage = self.read(addr)?;
            if sas.ss_family == (AddressFamily::Inet as u16) {
                if addrlen != size_of::<sockaddr_in>() {
                    bail!("Insufficient storage");
                }
                let sa: sockaddr_in = self.read(addr)?;
                Ok(SocketAddress::IPV4(u16::from_be(sa.sin_port)))
            } else {
                bail!("Unsupported address family")
            }
        }
    }

    fn write_data(&self, addr: u64, data: Vec<u8>) -> Result<usize, Error> {
        let mut buf: [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let length = data.len();
        trace!(
            "Going to write {:?} bytes into process memory at {:?}",
            length,
            addr
        );
        trace!("Writing {:?}", data);
        for (i, b) in data.iter().enumerate() {
            if i % size_of::<libc::c_long>() == 0 {
                // read the current value of this word from process memory so we
                // don't overwrite things we shouldn't
                let index = (i / size_of::<libc::c_long>()) * size_of::<libc::c_long>();
                let addr = addr + (index as u64);
                let data = self.read_data(addr, size_of::<libc::c_long>())?;
                assert!(data.len() == buf.len());
                // copy these data into our buffer
                for (i, b) in data.iter().enumerate() {
                    buf[i] = *b;
                }
            }
            buf[i % size_of::<libc::c_long>()] = *b;
            if ((i + 1) % size_of::<libc::c_long>() == 0) || i + 1 == length {
                let index = (i / size_of::<libc::c_long>()) * size_of::<libc::c_long>();
                let addr = addr + (index as u64);
                if (i + 1) % size_of::<libc::c_long>() != 0 {
                    // we're about to write a whole word, when we actually
                    // only want to write the contents of a prefix of that
                    // word. let's not!

                }
                let word = u64::from_ne_bytes(buf);
                trace!(
                    "Writing {:?} ({:?}) to process memory at {:?}",
                    buf,
                    word,
                    addr
                );
                ptrace::write(
                    self.tid,
                    addr as ptrace::AddressType,
                    word as *mut libc::c_void,
                )?;
            }
            // exit early if we're not iterating over whole vector
            if i + 1 == length {
                break;
            }
        }
        Ok(length)
    }

    unsafe fn write<T>(&self, addr: u64, t: T) -> Result<(), Error>
    where
        T: Copy,
    {
        trace!("size_of(T) is {:?} bytes", size_of::<T>());
        let p: *const T = &t; // the same operator is used as with references
        let p: *const u8 = p as *const u8; // convert between pointer types
        let s: &[u8] = slice::from_raw_parts(p, size_of::<T>());
        self.write_data(addr, s.into())?;
        Ok(())
    }

    fn write_socket_address(
        &self,
        addr_ptr: u64,
        addrlen: usize,
        addr: Option<SocketAddress>,
    ) -> Result<(), Error> {
        if let Some(addr) = addr {
            match addr {
                SocketAddress::IPV4(port) => {
                    if addrlen < size_of::<sockaddr_in>() {
                        bail!("Insufficient storage")
                    }
                    let localhost_le: u32 = std::net::Ipv4Addr::LOCALHOST.into();
                    let localhost = localhost_le.to_be();
                    let sa: sockaddr_in = sockaddr_in {
                        sin_family: (AddressFamily::Inet as u16),
                        sin_port: port.to_be(),
                        sin_addr: libc::in_addr { s_addr: localhost },
                        sin_zero: [0; 8],
                    };
                    unsafe {
                        self.write(addr_ptr, sa)?;
                    }
                }
                _ => bail!("attempt to write bad socket address"),
            }
        }
        Ok(())
    }

    fn get_syscall(&self) -> Result<Syscall, Error> {
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        let call_number = regs.orig_rax;
        let call = match call_number {
            0 => {
                //read()
                let fd = regs.rdi as i32;
                let buf_ptr = regs.rsi as u64;
                let count = regs.rdx as usize;
                if let Some(file) = self.files.borrow().get(&fd) {
                    if let File::TcpSocket(_) = file {
                        Ok(Syscall::RecvFrom(
                            fd,
                            file.clone(),
                            count,
                            MsgFlags::empty(),
                        ))
                    } else {
                        Ok(Syscall::Read(fd, file.clone(), buf_ptr, count))
                    }
                } else {
                    bail!("read() called on unknown file")
                }
            }
            1 => {
                //write()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    if let File::TcpSocket(_) = file {
                        let data = self.read_data(regs.rsi, regs.rdx as usize)?;
                        Ok(Syscall::SendTo(fd, file.clone(), None, data))
                    } else {
                        Ok(Syscall::Write(fd, file.clone()))
                    }
                } else {
                    bail!("write() called on unknown file")
                }
            }
            2 => {
                //open()
                let s = self.read_string(regs.rdi)?;
                let flags = regs.rsi as i32;
                if !is_read_only(flags) {
                    // snapshot file here: even though the open might not
                    // succeed, if it does it could create or truncate the file
                    self.snapshot.borrow_mut().snapshot_file(s.clone())?;
                }
                Ok(Syscall::Open(s, flags))
            }
            3 => {
                //close()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Close(fd, file.clone()))
                } else {
                    bail!("close() called on unknown file")
                }
            }
            4 => Ok(Syscall::Stat),
            5 => {
                //fstat()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Fstat(fd, file.clone()))
                } else {
                    bail!("fstat() called on unknown file")
                }
            }
            8 => Ok(Syscall::LSeek),
            9 => {
                // mmap(), only supported for global files for now
                let fd = regs.r8 as i32;
                if fd < 0 {
                    Ok(Syscall::MMap(fd, None))
                } else {
                    if let Some(file) = self.files.borrow().get(&fd) {
                        Ok(Syscall::MMap(fd, Some(file.clone())))
                    } else {
                        bail!("mmap() called on unknown file")
                    }
                }
            }
            10 => Ok(Syscall::MProtect),
            11 => Ok(Syscall::MUnmap),
            12 => Ok(Syscall::Brk),
            // TODO: figure out if I actually need to deal with signals
            13 => Ok(Syscall::SigAction),
            14 => Ok(Syscall::SigProcMask),
            16 => Ok(Syscall::IoCtl),
            20 => {
                //writev()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("writev() called on unknown file")
                }
            }
            21 => {
                // access()
                let s = self.read_string(regs.rdi)?;
                Ok(Syscall::Access(s))
            }
            22 => {
                // pipe()
                let addr = regs.rdi as u64;
                Ok(Syscall::Pipe(addr))
            }
            24 => Ok(Syscall::SchedYield),
            26 => Ok(Syscall::MSync),
            27 => Ok(Syscall::MInCore),
            28 => Ok(Syscall::MAdvise),
            32 => {
                // dup()
                let fd = regs.rdi as i32;
                Ok(Syscall::Dup(fd))
            }
            35 => {
                let timespec_ptr = regs.rdi;
                let t: libc::timespec = unsafe { self.read(timespec_ptr)? };
                let mut clock = Clock::from_timespec(&t);
                // this is a relative time
                clock.advance(&self.clock.borrow());
                let timeout_id = self.next_timeout_id();
                Ok(Syscall::NanoSleep(timeout_id, clock))
            }
            38 => {
                //setitimer
                // Currently we only allow programs to set the
                // profiling timer, which we ignore.
                let which = regs.rdi as i32;
                if which == libc::ITIMER_PROF {
                    Ok(Syscall::SetITimer)
                } else {
                    bail!("Unsupported ITimer {}", which);
                }
            }
            39 => Ok(Syscall::GetPid),
            41 => {
                // socket()
                let socket_family = regs.rdi as i32;
                let socket_type_and_flags = regs.rsi as i32;
                let socket_type = socket_type_and_flags & !(SockFlag::all().bits());
                let socket_protocol = regs.rdx as i32;
                // ensure this is a supported socket type
                if (socket_family == AddressFamily::Inet as i32
                    || socket_family == AddressFamily::Inet6 as i32)
                    && (socket_type == SockType::Datagram as i32
                        || socket_protocol == SockProtocol::Udp as i32)
                {
                    Ok(Syscall::UDPSocket)
                } else if (socket_family == AddressFamily::Inet as i32
                    || socket_family == AddressFamily::Inet6 as i32)
                    && (socket_type == SockType::Stream as i32
                        || socket_protocol == SockProtocol::Tcp as i32)
                {
                    // clear flags
                    regs.rsi = socket_type as u64;
                    self.set_registers(regs)?;
                    Ok(Syscall::TcpSocket)
                }
                // special-case wacky getaddrinfo() sockets
                else if (socket_family == 16 && socket_type == 3 && socket_protocol == 0)
                    || (socket_family == 1 && socket_type == 1 && socket_protocol == 0)
                {
                    Ok(Syscall::GetAddrInfoSocket)
                } else {
                    trace!(
                        "AF_INET={}, AF_INET6={}, SOCK_STREAM={}",
                        AddressFamily::Inet as i32,
                        AddressFamily::Inet6 as i32,
                        SockType::Stream as i32
                    );
                    bail!(
                        "Unsupported socket({}, {}, {})",
                        socket_family,
                        socket_type,
                        socket_protocol
                    );
                }
            }
            42 => {
                // connect()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    match sock {
                        File::TcpSocket(_) => {
                            let socket_address =
                                self.read_socket_address(regs.rsi, regs.rdx as usize)?;
                            Ok(Syscall::Connect(fd, sock.clone(), socket_address))
                        }
                        File::Special => Ok(Syscall::SpecialOp),
                        _ => bail!("connect() called on bad file {:?}", sock),
                    }
                } else {
                    bail!("connect() called on unknown file");
                }
            }
            43 => {
                // accept()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Accept(fd, sock.clone()))
                } else {
                    bail!("accept() called on unknown file")
                }
            }
            44 => {
                // sendto()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    if sock.is_special() {
                        Ok(Syscall::SpecialOp)
                    } else {
                        let socket_address = if regs.r8 != 0 {
                            Some(self.read_socket_address(regs.r8, regs.r9 as usize)?)
                        } else {
                            None
                        };
                        let data = self.read_data(regs.rsi, regs.rdx as usize)?;
                        Ok(Syscall::SendTo(fd, sock.clone(), socket_address, data))
                    }
                } else {
                    bail!("sendto() called on unknown file")
                }
            }
            45 => {
                // recvfrom()
                let fd = regs.rdi as i32;
                let size = regs.rdx as usize;
                let flags = MsgFlags::from_bits(regs.r10 as i32).unwrap();
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::RecvFrom(fd, sock.clone(), size, flags))
                } else {
                    bail!("recvfrom() called on unknown file")
                }
            }
            46 => {
                //sendmsg()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::SendMsg(fd, sock.clone()))
                } else {
                    bail!("sendmsg() called on unknown file")
                }
            }
            47 => {
                // recvmsg (only supported on special socks for now)
                let fd = regs.rdi as i32;
                if self.files.borrow().get(&fd).unwrap().is_special() {
                    Ok(Syscall::SpecialOp)
                } else {
                    bail!("recvmsg not yet supported");
                }
            }
            49 => {
                // bind()
                let fd = regs.rdi as i32;
                if self.files.borrow().get(&fd).unwrap().is_special() {
                    Ok(Syscall::SpecialOp)
                } else {
                    let socket_address = self.read_socket_address(regs.rsi, regs.rdx as usize)?;
                    Ok(Syscall::Bind(fd, socket_address))
                }
            }
            50 => {
                // listen()
                let fd = regs.rdi as i32;
                let backlog = regs.rsi as i32;
                Ok(Syscall::Listen(fd, backlog))
            }
            51 => {
                // getsockname()
                Ok(Syscall::GetSockName)
            }
            52 => {
                // getpeername()
                Ok(Syscall::GetPeerName)
            }
            54 => {
                // setsockopt()
                let fd = regs.rdi as i32;
                let level = regs.rsi as i32;
                let opt = regs.rdx as i32;
                Ok(Syscall::SetSockOpt(fd, level, opt))
            }
            56 => {
                // clone()
                let flags = CloneFlags::from_bits(regs.rdi as i32)
                    .ok_or(format_err!("Invalid clone() flags"))?;
                Ok(Syscall::Clone(flags))
            }
            63 => {
                // uname()
                Ok(Syscall::Uname)
            }
            72 => {
                // fcntl()
                use FcntlCmd::*;
                let fd = regs.rdi as i32;
                let cmd = regs.rsi as i32;
                let arg = regs.rdx as u64;
                if let Some(file) = self.files.borrow().get(&fd).clone() {
                    let inner = match cmd {
                        libc::F_GETFL => GetFl,
                        libc::F_SETFD => SetFd,
                        libc::F_SETFL => {
                            let opt = OFlag::from_bits(arg as i32).unwrap();
                            SetFl(opt)
                        }
                        _ => bail!("Bad fcntl {}", cmd),
                    };
                    Ok(Syscall::Fcntl(fd, file.clone(), inner))
                } else {
                    bail!("fcntl() called on bad file");
                }
            }
            73 => Ok(Syscall::FLock),
            74 => Ok(Syscall::Fsync),
            75 => Ok(Syscall::FDataSync),
            78 => Ok(Syscall::GetDents),
            79 => Ok(Syscall::GetCwd),
            83 => {
                // mkdir()
                let path = self.read_string(regs.rdi)?;
                Ok(Syscall::MkDir(path))
            }
            87 => {
                // unlink
                let path = self.read_string(regs.rdi)?;
                self.snapshot.borrow_mut().snapshot_file(path.clone())?;
                Ok(Syscall::Unlink(path))
            }
            88 => {
                // symlink
                let src_path = self.read_string(regs.rdi)?;
                let dst_path = self.read_string(regs.rsi)?;
                let mut snapshot = self.snapshot.borrow_mut();
                snapshot.snapshot_file(src_path.clone())?;
                snapshot.snapshot_file(dst_path.clone())?;
                Ok(Syscall::Symlink(src_path, dst_path))
            }
            89 => {
                // readlink()
                Ok(Syscall::ReadLink)
            }
            96 => Ok(Syscall::GetTimeOfDay),
            97 => Ok(Syscall::GetRLimit),
            99 => {
                // sysinfo()
                Ok(Syscall::SysInfo)
            }
            131 => Ok(Syscall::SigAltStack),
            158 => Ok(Syscall::ArchPrctl),
            186 => Ok(Syscall::GetTid),
            201 => {
                // time
                Ok(Syscall::Time)
            }

            // Futexes!
            202 => {
                let word = regs.rdi as u64;
                let op = regs.rsi as i32;
                let val = regs.rdx as i32;
                let uaddr2 = regs.r8 as u64;
                let val3 = regs.r9 as u32;
                let time_ptr = regs.r10 as u64;
                let futex = Futex::from_i32(op);
                if let Some(futex) = futex {
                    match futex {
                        // TODO: worry about private futexes?
                        Futex {
                            cmd: FutexCmd::WaitBitset,
                            private: true,
                            realtime: true,
                        } => Ok(Syscall::FutexTest),
                        Futex {
                            cmd: FutexCmd::Wait,
                            private: _,
                            realtime: _,
                        } => {
                            if time_ptr != 0 {
                                bail!("Timed futex waits not yet supported");
                            }
                            Ok(Syscall::FutexWait(word, val, FUTEX_BITSET_MATCH_ANY, None))
                        }
                        Futex {
                            cmd: FutexCmd::WaitBitset,
                            private: true,
                            realtime: false,
                        } => {
                            trace!("Waitbitset on {}, {}", word, val3);
                            let clock = if time_ptr != 0 {
                                let t: libc::timespec = unsafe { self.read(time_ptr)? };
                                let clock = Clock::from_timespec(&t);
                                let timeout_id = self.next_timeout_id();
                                Some((timeout_id, clock))
                            } else {
                                None
                            };
                            Ok(Syscall::FutexWait(word, val, val3, clock))
                        }
                        Futex {
                            cmd: FutexCmd::Wake,
                            private: _,
                            realtime: _,
                        } => Ok(Syscall::FutexWake(
                            word,
                            val as usize,
                            FUTEX_BITSET_MATCH_ANY,
                        )),
                        Futex {
                            cmd: FutexCmd::WakeBitset,
                            private: _,
                            realtime: _,
                        } => Ok(Syscall::FutexWake(word, val as usize, val3)),
                        Futex {
                            cmd: FutexCmd::CmpRequeue,
                            private: _,
                            realtime: _,
                        } => {
                            let val2 = time_ptr as u32; /* seriously */
                            Ok(Syscall::FutexCmpRequeue(
                                word,
                                val as usize,
                                uaddr2,
                                val2 as usize,
                            ))
                        }
                        Futex {
                            cmd: FutexCmd::WakeOp,
                            private: _,
                            realtime: _,
                        } => {
                            if let Some(args) = FutexWakeOpArgs::from_i32(val3 as i32) {
                                let val2 = time_ptr as u32;
                                Ok(Syscall::FutexWakeOp(
                                    word,
                                    val as usize,
                                    uaddr2,
                                    val2 as usize,
                                    args,
                                ))
                            } else {
                                bail!("Bad FUTEX_WAKE_OP args {:?}", val3)
                            }
                        }
                        _ => bail!("Bad futex op {:?}", futex),
                    }
                } else {
                    bail!("Bad futex op {}", op)
                }
            }
            203 => Ok(Syscall::SchedSetAffinity),
            204 => Ok(Syscall::SchedGetAffinity),
            213 => Ok(Syscall::EpollCreate),
            228 => {
                // clock_gettime
                // For now, we're just going to let these go through.
                Ok(Syscall::GetTime)
            }
            218 => Ok(Syscall::SetTidAddress),
            230 => {
                // clock_nanosleep
                let timespec_ptr = regs.rdx;
                let flags = regs.rsi;
                let t: libc::timespec = unsafe { self.read(timespec_ptr)? };
                let mut clock = Clock::from_timespec(&t);
                // this is a relative time
                if flags == 0 {
                    clock.advance(&self.clock.borrow());
                }
                let timeout_id = self.next_timeout_id();
                Ok(Syscall::NanoSleep(timeout_id, clock))
            }
            232 => {
                // epoll_wait
                let epfd = regs.rdi as i32;
                let events_ptr = regs.rsi as u64;
                let max_events = regs.rdx as usize;
                let timeout_millis = regs.r10 as i32;
                let timeout = if timeout_millis > -1 {
                    let clock = Clock::from_millis(timeout_millis as u32);
                    let timeout_id = self.next_timeout_id();
                    Some((timeout_id, clock))
                } else {
                    None
                };
                Ok(Syscall::EpollWait(epfd, events_ptr, max_events, timeout))
            }
            233 => {
                // epoll_ctl
                let epfd = regs.rdi as i32;
                let op: EpollOp = match regs.rsi as i32 {
                    x if x == EpollOp::EpollCtlAdd as i32 => EpollOp::EpollCtlAdd,
                    x if x == EpollOp::EpollCtlDel as i32 => EpollOp::EpollCtlDel,
                    x if x == EpollOp::EpollCtlMod as i32 => EpollOp::EpollCtlMod,
                    _ => bail!("Bad epoll op"),
                };
                let fd = regs.rdx as i32;
                let (flags, data) = match (op, regs.r10) {
                    (EpollOp::EpollCtlDel, _) => (None, None),
                    (_, addr) if addr != 0 => {
                        let event_struct: epoll_event = unsafe { self.read(addr)? };
                        (
                            Some(EpollFlags::from_bits(event_struct.events as i32).unwrap()),
                            Some(event_struct.u64),
                        )
                    }
                    _ => bail!("Bad epoll op and addr {:?} {}", op, regs.r10),
                };
                Ok(Syscall::EpollCtl(epfd, op, fd, flags, data))
            }
            257 => {
                // openat()
                let fd = regs.rdi as i32;
                // TODO: factor out this relative path logic (used in mkdirat() too)
                let path = {
                    let relative = self.read_string(regs.rsi)?;
                    let mut path = std::path::PathBuf::new();
                    if fd != libc::AT_FDCWD && !relative.starts_with("/") {
                        match self.files.borrow().get(&fd) {
                            Some(File::ReadFile(dirpath)) => path.push(dirpath.clone()),
                            file => {
                                bail!("openat called on bad file {:?} and path {}", file, relative)
                            }
                        };
                    }
                    path.push(relative);
                    path.to_str().unwrap().to_string()
                };
                let flags = regs.rdx as i32;
                if !is_read_only(flags) {
                    // snapshot file here: even though the open might not
                    // succeed, if it does it could create or truncate the file
                    self.snapshot.borrow_mut().snapshot_file(path.clone())?;
                }
                Ok(Syscall::Open(path, flags))
            }
            258 => {
                // mkdirat()
                let fd = regs.rdi as i32;
                let path = {
                    let relative = self.read_string(regs.rsi)?;
                    let mut path = std::path::PathBuf::new();
                    if fd != libc::AT_FDCWD && !relative.starts_with("/") {
                        match self.files.borrow().get(&fd) {
                            Some(File::ReadFile(dirpath)) => path.push(dirpath.clone()),
                            file => bail!(
                                "mkdirat called on bad file {:?} and path {}",
                                file,
                                relative
                            ),
                        };
                    }
                    path.push(relative);
                    path.to_str().unwrap().to_string()
                };
                Ok(Syscall::MkDir(path))
            }
            273 => Ok(Syscall::SetRobustList),
            283 => {
                // timerfd_create
                Ok(Syscall::TimerFdCreate)
            }
            285 => {
                // fallocate()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("fallocate() called on unknown file")
                }
            }
            286 => {
                // timerfd_settime
                let fd = regs.rdi as i32;
                let file = self.files.borrow().get(&fd).unwrap().clone();
                // ignore flags = regs.rsi
                let itimerspec_ptr = regs.rdx as u64;
                let itimer: libc::itimerspec = unsafe { self.read(itimerspec_ptr)? };
                use TimerCmd::*;
                let cmd = match (
                    itimer.it_value.tv_sec,
                    itimer.it_value.tv_nsec,
                    itimer.it_interval.tv_sec,
                    itimer.it_interval.tv_nsec,
                ) {
                    (0, 0, _, _) => Disarm,
                    (_, _, 0, 0) => {
                        let mut clock = Clock::from_timespec(&itimer.it_value);
                        clock.advance(&self.clock.borrow());
                        Arm(Clock::from_timespec(&itimer.it_value))
                    }
                    _ => ArmRecurring,
                };
                Ok(Syscall::TimerFdSetTime(file, cmd))
            }
            288 => {
                // accept4()
                let fd = regs.rdi as i32;
                // clear flags
                regs.r10 = 0;
                self.set_registers(regs)?;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Accept(fd, sock.clone())) // ignore flags for now
                } else {
                    bail!("accept() called on unknown file")
                }
            }
            289 => {
                // signalfd
                Ok(Syscall::SignalFd)
            }
            291 => {
                // epoll_create1
                Ok(Syscall::EpollCreate) // ignore flags for now
            }
            302 => Ok(Syscall::PRLimit64),
            // upcalls from application
            x if x >= 5000 => Ok(Syscall::Upcall((x - 5000) as usize)),
            _ => bail!(
                "Unsupported system call {} called by process {:?}",
                call_number,
                self
            ),
        };
        call
    }

    fn get_syscall_return(&mut self, call: Syscall) -> Result<SyscallReturn, Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let sys_ret = regs.rax as i64;
        let ret = if sys_ret < 0 {
            SyscallReturn::Failure(sys_ret)
        } else {
            SyscallReturn::Success(sys_ret)
        };
        match (call, ret) {
            (Syscall::Open(filename, flags), SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = if (flags & libc::O_ACCMODE) == libc::O_RDONLY {
                    // this is a read-only file, so we don't need to worry
                    // too much about it
                    File::ReadFile(filename)
                } else {
                    // this file might be written too, so we need to save a
                    // copy of it
                    self.snapshot
                        .borrow_mut()
                        .mark_for_restoration(filename.clone());
                    File::WriteFile(filename)
                };
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::Dup(fd1), SyscallReturn::Success(fd2)) => {
                let fd2 = fd2 as i32;
                trace!("Dup-ing {} to {}", fd1, fd2);
                if !self.files.borrow().contains_key(&fd1) {
                    bail!("No such fd {}", fd1);
                }
                let file = self.files.borrow().get(&fd1).unwrap().clone();
                self.files.borrow_mut().insert(fd2, file);
            }
            (Syscall::Pipe(addr), SyscallReturn::Success(_)) => {
                let fds: [i32; 2] = unsafe { self.read(addr)? };
                self.files.borrow_mut().insert(fds[0], File::Special);
                self.files.borrow_mut().insert(fds[1], File::Special);
            }
            (Syscall::Close(fd, _), SyscallReturn::Success(_)) => {
                trace!("Removing file {} from proc {:?}", fd, self);
                self.files.borrow_mut().remove(&fd);
            }
            (Syscall::Unlink(path), SyscallReturn::Success(_)) => {
                trace!("Marking {} for restoration (unlinked)", path);
                self.snapshot
                    .borrow_mut()
                    .mark_for_restoration(path.clone());
            }
            (Syscall::Symlink(src_path, dst_path), SyscallReturn::Success(_)) => {
                trace!(
                    "Marking {} and {} for restoration (symlink)",
                    src_path,
                    dst_path
                );
                let mut snapshot = self.snapshot.borrow_mut();
                snapshot.mark_for_restoration(src_path.clone());
                snapshot.mark_for_restoration(dst_path.clone());
            }
            (Syscall::UDPSocket, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::UDPSocket(None);
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::GetAddrInfoSocket, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::Special;
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::TcpSocket, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::TcpSocket(None);
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::Bind(fd, addr), SyscallReturn::Success(_)) => {
                let mut files = self.files.borrow_mut();
                let mut sock = files.get_mut(&fd);
                match sock.iter_mut().next() {
                    Some(File::UDPSocket(v)) => {
                        *v = Some(addr);
                    }
                    Some(File::TcpSocket(v)) => {
                        *v = Some(addr);
                    }
                    _ => {
                        bail!("bind() called on bad file");
                    }
                }
                // if let Some(sock) = sock {
                //     trace!("Binding {:?} to {:?}", sock, addr);
                //     let new_sock = match sock {
                //         File::UDPSocket(_) => File::UDPSocket(Some(addr)),
                //         File::TcpSocket(_) => File::TcpSocket(Some(addr)),
                //         _ => bail!("bind() on bad file {:?}", sock)
                //     };
                //     self.files.borrow_mut().insert(fd, new_sock);
            }
            (Syscall::TimerFdCreate, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let timeout_id = self.next_timeout_id();
                let file = File::TimerFd(timeout_id);
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::SignalFd, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::SignalFd;
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::EpollCreate, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::EpollFd(Vec::new(), Rc::new(RefCell::new(None)));
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::EpollCtl(epfd, op, fd, flags, data), SyscallReturn::Success(_)) => {
                use EpollOp::*;
                match self.files.borrow_mut().get_mut(&epfd) {
                    Some(File::EpollFd(fds, _)) => match op {
                        EpollCtlAdd => fds.push((fd, flags.unwrap(), data.unwrap())),
                        EpollCtlMod => {
                            let mut modded = false;
                            for entry in fds.iter_mut() {
                                if entry.0 == fd {
                                    modded = true;
                                    entry.1 = flags.unwrap();
                                    entry.2 = data.unwrap();
                                }
                            }
                            if !modded {
                                fds.push((fd, flags.unwrap(), data.unwrap()))
                            }
                        }
                        EpollCtlDel => {
                            let index = fds.iter().position(|e| e.0 == fd);
                            if let Some(index) = index {
                                fds.remove(index);
                            }
                        }
                    },
                    file => bail!("epoll_ctl on bad file {:?}", file),
                }
            }
            (Syscall::MkDir(path), SyscallReturn::Success(_)) => {
                // we successfully made a directory, so we're going to want to
                // remove it
                self.snapshot.borrow_mut().snapshot_directory(path);
            }
            _ => (),
        };
        Ok(ret)
    }

    fn stop_syscall(&mut self) -> Result<(), Error> {
        let mut regs = self.get_registers()?;
        regs.orig_rax = <u64>::max_value();
        self.set_registers(regs)?;
        Ok(())
    }

    fn wake_from_stopped_call(&self, call: Syscall) -> Result<(), Error> {
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        // fake a good return value depending on the call
        let mut regs = self.get_registers()?;
        regs.rax = match call {
            Syscall::SendTo(_, _, _, data) => data.len() as u64,
            Syscall::Upcall(_) => 42 as u64,
            _ => 0,
        };
        self.set_registers(regs)?;
        Ok(())
    }

    fn wake_from_stopped_call_with_ret(&self, ret: i32) -> Result<(), Error> {
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        // fake a good return value depending on the call
        let mut regs = self.get_registers()?;
        regs.rax = ret as u64;
        self.set_registers(regs)?;
        Ok(())
    }

    fn futex_wake_return(&self, wakes: usize) -> Result<(), Error> {
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        regs.rax = wakes as u64;
        self.set_registers(regs)?;
        Ok(())
    }

    /// Write addr and data into process's memory to simulate a recvfrom
    fn recvfrom_return(&self, addr: Option<SocketAddress>, data: Vec<u8>) -> Result<(), Error> {
        // get relevant registers before syscall
        let regs = self.get_registers()?;
        let buffer_ptr = regs.rsi;
        let buffer_len = regs.rdx as usize;
        let addr_ptr = regs.r8;
        let addr_len = regs.r9 as usize;

        // run syscall (which is a no-op)
        self.run_until_syscall()?;
        self.wait_on_syscall()?;

        // write to process memory
        trace!("Writing to process memory: {:?}", data);
        if buffer_len < data.len() {
            bail!("Data don't fit in buffer");
        }
        let written = self.write_data(buffer_ptr, data)?;
        if addr_ptr != 0 {
            trace!("Writing socket address");
            self.write_socket_address(addr_ptr, addr_len, addr)?;
        }
        // return data len
        let mut regs = self.get_registers()?;
        regs.rax = written as u64;
        self.set_registers(regs)?;
        Ok(())
    }

    // allow kernel to handle accept() call, don't wait on return, but get
    // register values
    fn accept_continue(&self) -> Result<(u64, usize), Error> {
        let regs = self.get_registers()?;
        let addr_ptr = regs.rsi;
        let addr_len = regs.rdx as usize;
        self.run_until_syscall()?;
        Ok((addr_ptr, addr_len))
    }

    fn accept_return(
        &mut self,
        addr_ptr: u64,
        addr_len: usize,
        addr: Option<SocketAddress>,
        local_addr: SocketAddress,
    ) -> Result<(), Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let sys_ret = regs.rax as i64;
        if sys_ret < 0 {
            bail!("accept() failed: {}", sys_ret);
        }
        let fd = sys_ret as i32;
        self.files
            .borrow_mut()
            .insert(fd, File::TcpSocket(Some(local_addr)));
        if addr_ptr != 0 {
            self.write_socket_address(addr_ptr, addr_len, addr)?;
        }
        Ok(())
    }

    fn connect_continue(&self, remote_addr: SocketAddress) -> Result<(), Error> {
        let regs = self.get_registers()?;
        let addr_ptr = regs.rsi;
        let addr_len = regs.rdx as usize;
        self.write_socket_address(addr_ptr, addr_len, Some(remote_addr))?;
        self.run_until_syscall()?;
        Ok(())
    }

    fn connect_return(&mut self, fd: i32, addr: SocketAddress) -> Result<(), Error> {
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        let mut sys_ret = regs.rax as i64;
        while sys_ret == -512 {
            // ERESTARTSYS
            trace!("Got ERESTARTSYS, restarting syscall (hopefully)");
            trace!("orig_rax is {}", regs.orig_rax);
            //regs.rax = regs.orig_rax;
            self.set_registers(regs)?;
            self.run_until_syscall()?;
            self.wait_on_syscall()?;
            self.run_until_syscall()?;
            self.wait_on_syscall()?;
            regs = self.get_registers()?;
            sys_ret = regs.rax as i64;
        }
        if sys_ret < 0 {
            bail!("connect() failed: {}", sys_ret);
        }
        self.files
            .borrow_mut()
            .insert(fd, File::TcpSocket(Some(addr)));
        Ok(())
    }

    fn epoll_timedout(&mut self) -> Result<(), Error> {
        self.run_until_syscall()?;
        self.wait_on_syscall()?;

        let mut regs = self.get_registers()?;
        regs.rax = 0 as u64;
        self.set_registers(regs)?;
        Ok(())
    }

    fn epoll_return(&mut self, event_ptr: u64, data: u64, event: u32) -> Result<(), Error> {
        self.run_until_syscall()?;
        self.wait_on_syscall()?;

        // write events into memory
        let e = epoll_event {
            events: event,
            u64: data, // yikes
        };
        unsafe {
            self.write(event_ptr, e)?;
        }

        // fake return value (always 1, bc one event)
        let mut regs = self.get_registers()?;
        regs.rax = 1 as u64;
        self.set_registers(regs)?;
        Ok(())
    }

    fn time_return(&mut self) -> Result<(), Error> {
        let sec = self.clock.borrow().to_timespec().tv_sec;
        self.stop_syscall()?;
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        regs.rax = sec as u64;
        let time_t_ptr = regs.rdi;
        if time_t_ptr != 0 {
            unsafe {
                self.write(time_t_ptr, sec as libc::time_t)?;
            }
        }
        self.set_registers(regs)?;
        Ok(())
    }

    fn gettimeofday_return(&mut self) -> Result<(), Error> {
        let time = self.clock.borrow().to_timespec();
        self.stop_syscall()?;
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        regs.rax = 0;
        let timespec_ptr = regs.rdi;
        if timespec_ptr != 0 {
            unsafe {
                self.write(timespec_ptr, time)?;
            }
        }
        self.set_registers(regs)?;
        Ok(())
    }

    fn gettime_return(&mut self) -> Result<(), Error> {
        let time = self.clock.borrow().to_timespec();
        self.stop_syscall()?;
        self.run_until_syscall()?;
        self.wait_on_syscall()?;
        let mut regs = self.get_registers()?;
        regs.rax = 0;
        let timespec_ptr = regs.rsi;
        if timespec_ptr != 0 {
            unsafe {
                self.write(timespec_ptr, time)?;
            }
        }
        self.set_registers(regs)?;
        Ok(())
    }
}

#[derive(Clone)]
enum HandleEpollReason {
    Message(SocketAddress),
    Timeout(TimeoutId),
    InitialWait,
    JustChecking,
}

enum HandleEpollWait {
    Message(SocketAddress),
    Timeout(TimeoutId),
}

enum HandleEpollResult {
    Return(u64, u64, u32),
    TimedOut,
    ContinueWaiting,
}

#[cfg(target_os = "linux")]
impl Handlers {
    pub fn new(config: &Config) -> Self {
        let protobuf_to_json = match &config.system {
            None => None,
            Some(sc) => match &sc.protobufs {
                None => None,
                Some(path) => Some(ProtobufToJson::new(path).expect("failed to read protobufs")),
            },
        };
        Self {
            nodes: config.nodes.clone(),
            procs: HashMap::new(),
            message_waiting_procs: HashMap::new(),
            timeout_waiting_procs: HashMap::new(),
            annotate_state_procs: HashMap::new(),
            address_to_name: HashMap::new(),
            tcp_channels: HashMap::new(),
            current_timeout: HashMap::new(),
            current_message: None,
            current_state: None,
            current_tcp_message: None,
            futexes: HashMap::new(),
            protobuf_to_json,
        }
    }

    pub fn servers(&self) -> Vec<&str> {
        let mut res = Vec::new();
        res.extend(self.nodes.keys().map(|s| s.as_str()));
        res
    }

    fn new_timeout(&mut self, procid: TracedProcessIdentifier, ty: String) {
        let mut timeout = data::Timeout::new();
        timeout.ty = ty;
        self.current_timeout.insert(procid, timeout);
    }

    fn new_message(&mut self, ty: String) {
        let mut message = data::Message::new();
        message.ty = ty;
        self.current_message = Some(message);
    }

    fn current_body(
        &mut self,
        procid: TracedProcessIdentifier,
    ) -> Result<&mut serde_json::Value, Error> {
        match self.current_timeout.get_mut(&procid) {
            Some(timeout) => return Ok(&mut timeout.body),
            None => (),
        }
        match self.current_message.as_mut() {
            Some(message) => return Ok(&mut message.body),
            None => (),
        }
        match self.current_state.as_mut() {
            Some(state) => return Ok(state),
            None => (),
        }
        bail!("No current body");
    }

    fn get_current_timeout(
        &mut self,
        procid: TracedProcessIdentifier,
        node: String,
        timeout_id: TimeoutId,
        clock: Clock,
    ) -> data::Timeout {
        let mut timeout = self
            .current_timeout
            .remove(&procid)
            .unwrap_or_else(|| data::Timeout::new());
        timeout.unique_id = serde_json::to_value(timeout_id.clone()).unwrap();
        timeout.to = node;
        let wire_timeout = WireTimeout { timeout_id, clock };
        timeout.raw = serde_json::to_value(wire_timeout).unwrap();
        timeout
    }

    fn get_current_message(
        &mut self,
        from: String,
        to: String,
        data: serde_json::Value,
    ) -> data::Message {
        let mut message = self
            .current_message
            .take()
            .unwrap_or_else(|| data::Message::new());
        message.from = from;
        message.to = to;
        message.raw = data;
        message
    }

    fn send_tcp_message(&mut self, response: &mut data::Response) -> Result<(), Error> {
        if let Some((addr, bytes)) = self.current_tcp_message.take() {
            match &addr {
                SocketAddress::TcpStream(name, id) => {
                    let channel = self.tcp_channels.get(&(name.to_string(), *id)).unwrap();
                    let from = name;
                    let to = self.address_to_name.get(&addr).unwrap();
                    let raw = WireMessage {
                        from: Some(addr.clone()),
                        to: channel.remote_addr.clone().unwrap(),
                        data: MessageData::TcpMessage(bytes),
                    };
                    let data = serde_json::to_value(&raw).unwrap();
                    let message = self.get_current_message(from.to_string(), to.to_string(), data);
                    response.messages.push(message);
                }
                _ => bail!("Bad TCP address"),
            }
        }
        Ok(())
    }

    fn handle_epoll(
        &mut self,
        procid: TracedProcessIdentifier,
        call: Syscall,
        reason: HandleEpollReason,
        response: &mut data::Response,
    ) -> Result<HandleEpollResult, Error> {
        if let Syscall::EpollWait(epfd, events_ptr, _, timeout) = call.clone() {
            let mut return_entry: Option<(i32, EpollFlags, u64)> = None;
            let mut waits: Vec<HandleEpollWait> = Vec::new();
            if let Some((timeout_id, _clock)) = timeout.clone() {
                waits.push(HandleEpollWait::Timeout(timeout_id.clone()));
                if let HandleEpollReason::Timeout(ref id) = reason {
                    if timeout_id == id.clone() {
                        // really horrid hack, here
                        return_entry = Some((-1, EpollFlags::empty(), 0));
                    }
                }
            }
            let proc = self
                .procs
                .get_mut(&procid)
                .expect(&format!("Bad process identifier {:?}", procid));
            {
                let all_files = proc.files.borrow();
                let epoll_file = all_files.get(&epfd).unwrap();
                match epoll_file {
                    File::EpollFd(fds, _) => {
                        let files: Vec<_> = fds
                            .iter()
                            .map(|(fd, flags, data)| {
                                (
                                    fd,
                                    all_files.get(&fd).unwrap().clone(),
                                    flags.clone(),
                                    data.clone(),
                                )
                            })
                            .collect();
                        for (fd, file, flags, data) in files.iter() {
                            use File::*;
                            match file {
                                TcpSocket(Some(sockaddr)) => {
                                    // our sockets are always EPOLLOUT-ready
                                    waits.push(HandleEpollWait::Message(sockaddr.clone()));
                                    if let HandleEpollReason::Message(ref addr) = reason {
                                        if *sockaddr == addr.clone()
                                            && flags.intersects(EpollFlags::EPOLLIN)
                                        {
                                            warn!("found this message's entry, recording it: {} {:?} {:?} {}",
                                                  fd, file, flags, data);
                                            return_entry = Some((**fd, *flags, *data));
                                        }
                                    }
                                    if flags.intersects(EpollFlags::EPOLLOUT) {
                                        // return this fd iff we're not returning something else
                                        return_entry = return_entry.or(Some((**fd, *flags, *data)));
                                    }
                                }
                                TimerFd(timeout_id) => {
                                    waits.push(HandleEpollWait::Timeout(timeout_id.clone()));
                                    if let HandleEpollReason::Timeout(ref id) = reason {
                                        if *timeout_id == id.clone()
                                            && flags.intersects(EpollFlags::EPOLLIN)
                                        {
                                            return_entry = Some((**fd, *flags, *data));
                                        }
                                    }
                                }
                                SignalFd => (),
                                Special => (),
                                f => bail!("Bad file {:?} in epoll", f),
                            }
                        }
                    }
                    _ => bail!("bad epoll"),
                }
            }
            // at this point, we have a complete list of waits and maybe a return value
            match return_entry {
                Some((fd, flags, data)) => {
                    // we're going to return, but we need to:
                    // 1. set "waiting" to None
                    // 2. if flags & EPOLLONESHOT, remove the fd from the list
                    // 3. stop waiting on all of these fds
                    // 4. clear the call's timeout, if there is one
                    {
                        let mut all_files = proc.files.borrow_mut();
                        let epoll_file = all_files.get_mut(&epfd).unwrap();
                        match epoll_file {
                            File::EpollFd(fds, waiting) => {
                                waiting.replace(None);
                                if flags.intersects(EpollFlags::EPOLLONESHOT) {
                                    let index = fds.iter().position(|e| e.0 == fd).unwrap();
                                    fds.remove(index);
                                }
                            }
                            _ => bail!("bad epoll"),
                        }
                    }
                    for wait in waits {
                        match wait {
                            HandleEpollWait::Message(addr) => {
                                self.message_waiting_procs.remove(&addr.clone());
                            }
                            HandleEpollWait::Timeout(timeout_id) => {
                                self.timeout_waiting_procs.remove(&timeout_id.clone());
                            }
                        }
                    }
                    if let Some((timeout_id, _clock)) = timeout {
                        self.clear_timeout(procid.name.clone(), response, &timeout_id)
                    }
                    if fd < 1 {
                        Ok(HandleEpollResult::TimedOut)
                    } else {
                        Ok(HandleEpollResult::Return(
                            events_ptr,
                            data,
                            flags.bits() as u32,
                        ))
                    }
                }
                None => {
                    // we're going to return, but we need to record that we are waiting
                    {
                        let mut all_files = proc.files.borrow_mut();
                        let epoll_file = all_files.get_mut(&epfd).unwrap();
                        match epoll_file {
                            File::EpollFd(_fds, waiting) => {
                                waiting.replace(Some((procid.clone(), call.clone())));
                            }
                            _ => bail!("bad epoll"),
                        }
                    }
                    for wait in waits {
                        match wait {
                            HandleEpollWait::Message(addr) => {
                                self.message_waiting_procs
                                    .insert(addr.clone(), (procid.clone(), call.clone()));
                            }
                            HandleEpollWait::Timeout(timeout_id) => {
                                self.timeout_waiting_procs
                                    .insert(timeout_id.clone(), (procid.clone(), call.clone()));
                            }
                        }
                    }
                    if let Some((timeout_id, clock)) = timeout {
                        match reason {
                            HandleEpollReason::InitialWait => {
                                let timeout = self.get_current_timeout(
                                    procid.clone(),
                                    procid.name.clone(),
                                    timeout_id,
                                    clock,
                                );
                                warn!("Setting timeout {:?} (epoll wait)", timeout);
                                response.timeouts.push(timeout);
                            }
                            _ => (),
                        }
                    }
                    Ok(HandleEpollResult::ContinueWaiting)
                }
            }
        } else {
            bail!("bad epoll");
        }
    }

    fn clear_timeout(&self, node: String, response: &mut data::Response, timeout_id: &TimeoutId) {
        let tid = serde_json::to_value(timeout_id).unwrap();
        // if we've set this timeout, we should clear it
        response.timeouts.retain(|t| t.unique_id != tid);

        // we might have set it before, so we should also tell Oddity to clear it
        let mut t = data::Timeout::clear(tid);
        t.to = node;
        response.cleared_timeouts.push(t);
    }

    fn write_object_field(
        &mut self,
        procid: TracedProcessIdentifier,
        path: &str,
        v: serde_json::Value,
    ) -> Result<(), Error> {
        let mut obj = self.current_body(procid)?;
        let mut fields: Vec<&str> = path.split(".").collect();
        while let Some(field) = fields.pop() {
            if !obj.is_object() {
                *obj = json!({});
            }
            obj = obj
                .as_object_mut()
                .unwrap()
                .entry(field)
                .or_insert(json!({}));
        }
        *obj = v;
        Ok(())
    }

    /// Fills the response from any non-blocking syscalls made by proc procid
    ///
    /// Should be called after any outstanding syscalls have been
    /// processed--i.e., a syscall exit (or process start) is the most recent
    /// event
    fn fill_response(
        &mut self,
        procid: TracedProcessIdentifier,
        response: &mut data::Response,
    ) -> Result<(), Error> {
        let mut stack = Vec::<TracedProcessIdentifier>::new();
        stack.push(procid);
        while let Some(procid) = stack.pop() {
            trace!("Filling response from process {:?}", procid);
            let proc = self
                .procs
                .get_mut(&procid)
                .expect(&format!("Bad process identifier {:?}", procid));
            proc.run_until_syscall()?;
            let call = proc.get_syscall()?;
            trace!("Process {} called Syscall {:?}", proc, call);
            // check for unsupported calls and panic if necessary
            match &call {
                Syscall::Read(_, file, _, _) => match file {
                    File::ReadFile(_) | File::WriteFile(_) | File::Special | File::Random => (),
                    _ => bail!("Unsupported read of file {:?}", file),
                },
                Syscall::Write(_, file) => match file {
                    File::Special => (),
                    File::WriteFile(_) => (),
                    _ => bail!("Unsupported write to file {:?}", file),
                },
                Syscall::MMap(_, Some(file)) => match file {
                    File::ReadFile(_) => (),
                    File::WriteFile(_) => (),
                    _ => bail!("Unsupported mmap on file {:?}", file),
                },
                Syscall::RecvFrom(_, file, _, _) => match file {
                    File::UDPSocket(Some(_)) => (),
                    File::TcpSocket(Some(SocketAddress::TcpStream(_, _))) => (),
                    _ => bail!("Unsupported recvfrom on file {:?}", file),
                },
                Syscall::Accept(_, file) => match file {
                    File::TcpSocket(Some(_)) => (),
                    _ => bail!("Unsupported accept on file {:?}", file),
                },
                Syscall::SendTo(_, file, addr, _) => match (file, addr) {
                    (File::UDPSocket(_), Some(_)) => (),
                    (File::TcpSocket(Some(SocketAddress::TcpStream(_, _))), _) => (),
                    _ => bail!("Unsupported sendto on file {:?}", file),
                },
                Syscall::SendMsg(_, file) => match file {
                    File::TcpSocket(Some(SocketAddress::TcpStream(_, _))) => (),
                    _ => bail!("Unsupported sendto on file {:?}", file),
                },
                Syscall::Connect(_, file, _) => match file {
                    File::TcpSocket(_) => (),
                    _ => bail!("Unsupported connect on file {:?}", file),
                },
                Syscall::SetSockOpt(_, level, opt) => match (*level, *opt) {
                    (libc::SOL_SOCKET, libc::SO_REUSEADDR) => (),
                    (libc::IPPROTO_TCP, libc::TCP_NODELAY) => (),
                    (libc::SOL_SOCKET, libc::SO_KEEPALIVE) => (),
                    (libc::IPPROTO_TCP, libc::TCP_KEEPIDLE) => (),
                    (libc::IPPROTO_TCP, libc::TCP_KEEPINTVL) => (),
                    (libc::IPPROTO_TCP, libc::TCP_KEEPCNT) => (),
                    _ => bail!("Unsupported setsockopt: {}/{}", level, opt),
                },
                _ => (),
            }
            match &call {
                Syscall::Open(path, _flags)
                    if (path.starts_with("/dev/") || path.starts_with("proc")) =>
                {
                    // opening non-file file, we will have to be careful here
                    if path == "/dev/urandom" {
                        // we're not going to allow this to go through
                        proc.run_until_syscall()?;
                        let ret = proc.get_syscall_return(call.clone())?;
                        if let SyscallReturn::Success(fd) = ret {
                            let fd = fd as i32;
                            proc.files.borrow_mut().insert(fd, File::Random);
                        }
                        stack.push(procid.clone());
                    } else {
                        bail!("Process tried to open illegal file {}", path);
                    }
                }
                Syscall::Read(_, File::Random, buf_ptr, count) => {
                    // we need to write some data into this process's memory. fun!
                    proc.stop_syscall()?;
                    proc.wake_from_stopped_call_with_ret(*count as i32)?;
                    let buf: Vec<u8> = vec![2; *count];
                    assert!(*count == buf.len());
                    proc.write_data(*buf_ptr, buf)?;
                    trace!("Faked a random read of len {}", *count);
                    stack.push(procid.clone());
                }
                Syscall::RecvFrom(_, File::UDPSocket(Some(addr)), _, _) => {
                    proc.stop_syscall()?;
                    self.message_waiting_procs
                        .insert(addr.clone(), (procid.clone(), call.clone()));
                    // we're blocking, so we're done here
                }
                Syscall::RecvFrom(_, File::TcpSocket(Some(to_addr)), _size, flags) => {
                    let to_addr = to_addr.clone();
                    let channel = {
                        match &to_addr {
                            SocketAddress::TcpStream(name, id) => {
                                self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                            }
                            _ => bail!("unexpected address"),
                        }
                    };
                    let delivered = *channel.delivered.borrow();
                    if delivered > 0 || flags.intersects(MsgFlags::MSG_DONTWAIT) {
                        proc.run_until_syscall()?;
                        let ret = proc.get_syscall_return(call)?;
                        trace!("Process {} got syscall return {:?}", proc, ret);
                        if let SyscallReturn::Success(value) = ret {
                            *channel.delivered.borrow_mut() -= value as usize;
                        }
                        stack.push(procid.clone());
                    } else {
                        self.message_waiting_procs
                            .insert(to_addr.clone(), (procid.clone(), call.clone()));
                    }
                }
                Syscall::Connect(_fd, File::TcpSocket(from_addr), to_addr) => {
                    // don't stop the process
                    if let Some(to) = self.address_to_name.get(&to_addr) {
                        let counter = proc.next_counter();
                        let listener = TcpListener::bind(("localhost", 0)).unwrap();
                        let mut tcp_channel = TcpChannel::new();
                        tcp_channel.listener = Some(listener);
                        self.tcp_channels
                            .insert((procid.name.clone(), counter), tcp_channel);
                        let raw = WireMessage {
                            from: from_addr.clone(),
                            to: to_addr.clone(),
                            data: MessageData::TcpConnect(counter),
                        };
                        let mut message = data::Message::new();
                        message.from = procid.name.clone();
                        message.to = to.clone();
                        message.ty = "Tcp-Connect".to_string();
                        message.raw = serde_json::to_value(&raw).unwrap();
                        response.messages.push(message);
                        let channel_addr = SocketAddress::TcpStream(procid.name.clone(), counter);
                        self.address_to_name
                            .insert(channel_addr.clone(), to.clone());
                        self.message_waiting_procs
                            .insert(channel_addr, (procid.clone(), call.clone()));
                    // we're blocking waiting for a response, so we're done here
                    } else {
                        bail!("Connect to unknown address {:?}", to_addr);
                    }
                }
                Syscall::Accept(_, File::TcpSocket(Some(addr))) => {
                    // don't stop the process
                    self.message_waiting_procs
                        .insert(addr.clone(), (procid.clone(), call.clone()));
                }
                Syscall::NanoSleep(timeout_id, clock) => {
                    proc.stop_syscall()?;
                    self.timeout_waiting_procs
                        .insert(timeout_id.clone(), (procid.clone(), call.clone()));
                    let timeout = self.get_current_timeout(
                        procid.clone(),
                        procid.name.clone(),
                        timeout_id.clone(),
                        clock.clone(),
                    );
                    warn!("Setting timeout {:?} (nanosleep)", timeout);
                    response.timeouts.push(timeout);
                    // we're blocking, so we're done here
                }
                Syscall::TimerFdSetTime(file, cmd) => {
                    if let File::TimerFd(timeout_id) = file {
                        proc.stop_syscall()?;
                        proc.wake_from_stopped_call(call.clone())?;
                        use TimerCmd::*;
                        match cmd {
                            ArmRecurring => {
                                bail!("recurring timeouts not supported");
                            }
                            Arm(clock) => {
                                let timeout = self.get_current_timeout(
                                    procid.clone(),
                                    procid.name.clone(),
                                    timeout_id.clone(),
                                    clock.clone(),
                                );
                                warn!("Setting timeout {:?} (timerfd_settime)", timeout);
                                response.timeouts.push(timeout);
                            }
                            Disarm => {
                                self.clear_timeout(procid.name.clone(), response, &timeout_id)
                            }
                        }
                        stack.push(procid.clone());
                    } else {
                        bail!("timerfd_settime called on bad file {:?}", file);
                    }
                }
                // handle UDP send
                Syscall::SendTo(_, File::UDPSocket(from_addr), Some(to_addr), data) => {
                    proc.stop_syscall()?;
                    if let Some(to) = self.address_to_name.get(&to_addr) {
                        proc.wake_from_stopped_call(call.clone())?;
                        let raw = WireMessage {
                            from: from_addr.clone(),
                            to: to_addr.clone(),
                            data: MessageData::Data(data.clone()),
                        };
                        let message = self.get_current_message(
                            procid.name.clone(),
                            to.clone(),
                            serde_json::to_value(&raw).unwrap(),
                        );
                        response.messages.push(message);
                        // don't execute ordinary syscall return handling
                        // keep filling response
                        stack.push(procid.clone());
                    } else {
                        bail!("Send to unknown address {:?}", to_addr);
                    }
                }
                // handle TCP send
                Syscall::SendTo(_, File::TcpSocket(Some(to_addr)), _, data) => {
                    let to_addr = to_addr.clone();
                    let data_len = data.len();
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    let channel = {
                        match &to_addr {
                            SocketAddress::TcpStream(name, id) => {
                                self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                            }
                            _ => bail!("unexpected address"),
                        }
                    };
                    channel.send(data_len);
                    self.current_tcp_message = match self.current_tcp_message.take() {
                        None => Some((to_addr.clone(), data_len)),
                        Some((addr, len)) => {
                            if addr == to_addr {
                                Some((to_addr.clone(), len + data_len))
                            } else {
                                self.send_tcp_message(response)?;
                                Some((to_addr.clone(), data_len))
                            }
                        }
                    };
                    stack.push(procid.clone());
                }
                Syscall::SendMsg(_, File::TcpSocket(Some(to_addr))) => {
                    let to_addr = to_addr.clone();
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    if let SyscallReturn::Success(data_len) = ret {
                        let data_len = data_len as usize;
                        let channel = {
                            match &to_addr {
                                SocketAddress::TcpStream(name, id) => {
                                    self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                                }
                                _ => bail!("unexpected address"),
                            }
                        };
                        channel.send(data_len);
                        self.current_tcp_message = match self.current_tcp_message.take() {
                            None => Some((to_addr.clone(), data_len)),
                            Some((addr, len)) => {
                                if addr == to_addr {
                                    Some((to_addr.clone(), len + data_len))
                                } else {
                                    self.send_tcp_message(response)?;
                                    Some((to_addr.clone(), data_len))
                                }
                            }
                        };
                        stack.push(procid.clone());
                    }
                }
                Syscall::Clone(_) => {
                    // TODO: handle different clone flags differently?
                    let (tid, child) = proc.get_cloned_child()?;
                    // let parent finish syscall before starting to execute child
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
                    // Now execute child
                    trace!("New child process {:?}", child);
                    let child_id = procid.child_process(tid);
                    self.procs.insert(child_id.clone(), child);
                    // fill response from child process
                    stack.push(child_id.clone());
                }
                // TODO: find a way to avoid this duplication
                Syscall::Bind(_, addr) => {
                    self.address_to_name
                        .insert(addr.clone(), procid.name.clone());
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
                }
                Syscall::FutexWait(futex, val, _, timeout) => {
                    // Add us to the queue for this futex
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let current_value: i32 = unsafe { proc.read(futex)? };
                    if current_value != *val {
                        trace!(
                            "Futex value {} doesn't match {}, not sleeping",
                            current_value,
                            *val
                        );
                        proc.wake_from_stopped_call_with_ret(-1 * libc::EAGAIN)?;
                        stack.push(procid.clone());
                    } else {
                        let waiters = self.futexes.entry(futex).or_insert_with(|| VecDeque::new());
                        trace!(
                            "Proc {:?} going on queue for futex {} with call {:?}",
                            procid.clone(),
                            futex,
                            call
                        );
                        waiters.push_back((procid.clone(), call.clone()));
                        if let Some((timeout_id, clock)) = timeout {
                            // this is a timed wait, so we need to add a timeout to the response
                            let timeout = self.get_current_timeout(
                                procid.clone(),
                                procid.name.clone(),
                                timeout_id.clone(),
                                clock.clone(),
                            );
                            self.timeout_waiting_procs
                                .insert(timeout_id.clone(), (procid.clone(), call.clone()));
                            warn!("Setting timeout {:?} (futex wait)", timeout);
                            response.timeouts.push(timeout);
                        }
                    }
                    // We're done here--we're waiting to be awoken
                }
                Syscall::FutexWake(futex, max_wakes, bitset) => {
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let max_wakes = *max_wakes;
                    let bitset = *bitset;
                    // let's see if a process is actually waiting on this futex
                    let waiters = self.futexes.entry(futex).or_insert_with(|| VecDeque::new());

                    /*
                    We want to wake as many processes as we can, such that:
                    1. We wake at most *max_wakes* processes
                    2. We wake only processes matching the bitset
                     */
                    let mut wakes = Vec::<(TracedProcessIdentifier, Syscall)>::new();
                    let mut i = 0;
                    while i < waiters.len() && wakes.len() < max_wakes {
                        match waiters[i].1 {
                            Syscall::FutexWait(_, _, waiter_bitset, _)
                                if bitset & waiter_bitset != 0 =>
                            {
                                wakes.push(waiters.remove(i).unwrap());
                            }
                            _ => {
                                // ignore this one
                                i += 1;
                            }
                        }
                    }
                    trace!("Waking {:?}, leaving {:?}", wakes, waiters);
                    // return to waking process
                    proc.futex_wake_return(wakes.len())?;
                    stack.push(procid.clone());

                    // wake other processes
                    for (waiter_id, call) in wakes {
                        trace!("Waking process {:?}", waiter_id);
                        let waiter = self
                            .procs
                            .get_mut(&waiter_id)
                            .expect(&format!("Bad process identifier {:?}", waiter_id));
                        waiter.wake_from_stopped_call(call.clone())?;
                        stack.push(waiter_id.clone());
                        match call {
                            Syscall::FutexWait(_, _, _, Some((timeout_id, _))) => {
                                self.clear_timeout(waiter_id.name.clone(), response, &timeout_id);
                                self.timeout_waiting_procs.remove(&timeout_id);
                            }
                            _ => (),
                        }
                    }
                }
                Syscall::FutexCmpRequeue(futex, max_wakes, futex2, max_moves) => {
                    // TODO: worry about CMP? i think we don't need to due to
                    // coarse scheduling granularity
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let futex2 = *futex2;
                    let max_wakes = *max_wakes;
                    let max_moves = *max_moves;
                    // let's see if a process is actually waiting on this futex
                    let waiters = self.futexes.entry(futex).or_insert_with(|| VecDeque::new());

                    let max_wakes = std::cmp::min(max_wakes, waiters.len());
                    let wakes: Vec<_> = waiters.drain(0..max_wakes).collect();
                    let max_moves = std::cmp::min(max_moves, waiters.len());
                    let mut moves: VecDeque<_> = waiters.drain(0..max_moves).collect();
                    trace!(
                        "Waking {:?}, requeueing {:?}, leaving {:?}",
                        wakes,
                        moves,
                        waiters
                    );
                    // return to waking process
                    proc.futex_wake_return(wakes.len())?;
                    stack.push(procid.clone());

                    // wake waking processes
                    for (waiter_id, call) in wakes {
                        trace!("Waking process {:?}", waiter_id);
                        let waiter = self
                            .procs
                            .get_mut(&waiter_id)
                            .expect(&format!("Bad process identifier {:?}", waiter_id));
                        waiter.wake_from_stopped_call(call.clone())?;
                        stack.push(waiter_id.clone());
                        match call {
                            Syscall::FutexWait(_, _, _, Some((timeout_id, _))) => {
                                self.clear_timeout(waiter_id.name.clone(), response, &timeout_id);
                                self.timeout_waiting_procs.remove(&timeout_id);
                            }
                            _ => (),
                        }
                    }
                    // clear timeouts for moving processes: these can't be woken via timeout anymore
                    for (waiter_id, call) in moves.clone() {
                        match call {
                            Syscall::FutexWait(_, _, _, Some((timeout_id, _))) => {
                                trace!("Clearing timeout for {:?}", waiter_id);
                                self.clear_timeout(waiter_id.name.clone(), response, &timeout_id);
                                self.timeout_waiting_procs.remove(&timeout_id);
                            }
                            _ => (),
                        }
                    }

                    // move moving processes
                    let other_waiters = self
                        .futexes
                        .entry(futex2)
                        .or_insert_with(|| VecDeque::new());
                    other_waiters.append(&mut moves);
                }
                Syscall::FutexWakeOp(futex, max_wakes, futex2, max_wakes2, args) => {
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let futex2 = *futex2;
                    let max_wakes = *max_wakes;
                    let max_wakes2 = *max_wakes2;
                    let args = args.clone();

                    // first we'll perform the op
                    let old_value = unsafe {
                        let value: i32 = proc.read(futex2)?;
                        let new_value = match args.op {
                            FutexWakeOp::Set => args.oparg,
                            FutexWakeOp::Add => value + args.oparg,
                            FutexWakeOp::Or => value | args.oparg,
                            FutexWakeOp::AndN => value & !(args.oparg),
                            FutexWakeOp::Xor => value ^ args.oparg,
                        };
                        proc.write(futex2, new_value)?;
                        value
                    };
                    trace!("FUTEX_WAKE_OP old value is {}", old_value);
                    let wake2 = match args.cmp {
                        FutexWakeCmp::Eq => old_value == args.cmparg,
                        FutexWakeCmp::Ne => old_value != args.cmparg,
                        FutexWakeCmp::Lt => old_value < args.cmparg,
                        FutexWakeCmp::Le => old_value <= args.cmparg,
                        FutexWakeCmp::Gt => old_value > args.cmparg,
                        FutexWakeCmp::Ge => old_value >= args.cmparg,
                    };
                    // wake up max_wakes waiters from futex
                    let waiters = self.futexes.entry(futex).or_insert_with(|| VecDeque::new());
                    let max_wakes = std::cmp::min(max_wakes, waiters.len());
                    let mut wakes: Vec<_> = waiters.drain(0..max_wakes).collect();
                    // maybe wake up max_wakes2 waiters from futex2
                    if wake2 {
                        let waiters2 = self
                            .futexes
                            .entry(futex2)
                            .or_insert_with(|| VecDeque::new());
                        let max_wakes2 = std::cmp::min(max_wakes2, waiters2.len());
                        wakes.extend(waiters2.drain(0..max_wakes2));
                    }
                    trace!("FUTEX_WAKE_OP Waking {:?}", wakes);
                    // return to waking process
                    proc.futex_wake_return(wakes.len())?;
                    stack.push(procid.clone());

                    // wake waking processes
                    for (waiter_id, call) in wakes {
                        trace!("Waking process {:?}", waiter_id);
                        let waiter = self
                            .procs
                            .get_mut(&waiter_id)
                            .expect(&format!("Bad process identifier {:?}", waiter_id));
                        waiter.wake_from_stopped_call(call.clone())?;
                        stack.push(waiter_id.clone());
                        match call {
                            Syscall::FutexWait(_, _, _, Some((timeout_id, _))) => {
                                self.clear_timeout(waiter_id.name.clone(), response, &timeout_id);
                                self.timeout_waiting_procs.remove(&timeout_id);
                            }
                            _ => (),
                        }
                    }
                }
                Syscall::EpollWait(_epfd, _events_ptr, _max_events, _timeout) => {
                    use HandleEpollReason::*;
                    use HandleEpollResult::*;
                    proc.stop_syscall()?;
                    let res =
                        self.handle_epoll(procid.clone(), call.clone(), InitialWait, response)?;
                    match res {
                        ContinueWaiting => (),
                        TimedOut => bail!("timed out immediately, which shouldn't happen"),
                        Return(event_ptr, data, why) => {
                            // epoll_wait should return immediately
                            let proc = self
                                .procs
                                .get_mut(&procid.clone())
                                .expect(&format!("Bad process identifier {:?}", procid));
                            proc.epoll_return(event_ptr, data, why)?;
                            stack.push(procid.clone());
                        }
                    }
                }
                Syscall::EpollCtl(epfd, op, _fd, _flags, _data) => {
                    use File::*;
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call.clone())?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
                    if (*op == EpollOp::EpollCtlAdd || *op == EpollOp::EpollCtlMod)
                        && ret.is_success()
                    {
                        trace!("checking to see if we need to wake up the epoll waiter");
                        let waiting = {
                            let all_files = proc.files.borrow();
                            let epfile = all_files.get(&epfd).unwrap();
                            let waiting = match epfile {
                                EpollFd(_, waiting) => waiting,
                                f => bail!("epoll_ctl on bad file {:?}", f),
                            };
                            let waiting = waiting.borrow().clone();
                            waiting
                        };
                        trace!("Waiting is {:?}", waiting);
                        if let Some((procid, call)) = waiting {
                            let ret = self.handle_epoll(
                                procid.clone(),
                                call.clone(),
                                HandleEpollReason::JustChecking,
                                response,
                            )?;
                            match ret {
                                HandleEpollResult::Return(events_ptr, data, why) => {
                                    // we need to wake up this process
                                    trace!("waking up waiter");
                                    let waiter = self
                                        .procs
                                        .get_mut(&procid)
                                        .expect(&format!("Bad process identifier {:?}", procid));
                                    waiter.epoll_return(events_ptr, data, why)?;
                                    stack.push(procid.clone());
                                }
                                HandleEpollResult::TimedOut => {
                                    bail!("Epoll timed out on epollctl--impossible");
                                }
                                HandleEpollResult::ContinueWaiting => (),
                            }
                        }
                    }
                }
                // we want to block attempts to make things non-blocking
                Syscall::Fcntl(_, file, FcntlCmd::SetFl(flags))
                    if !file.is_special() && flags.intersects(OFlag::O_NONBLOCK) =>
                {
                    trace!("Stopping attempt to make something non-blocking");
                    proc.stop_syscall()?;
                    proc.wake_from_stopped_call(call)?;
                    stack.push(procid.clone());
                }
                Syscall::GetTime => {
                    trace!("GetTime called; lying about the time");
                    proc.gettime_return()?;
                    stack.push(procid.clone());
                }
                Syscall::GetTimeOfDay => {
                    trace!("GetTimeOfDay called; lying about the time");
                    proc.gettimeofday_return()?;
                    stack.push(procid.clone());
                }
                Syscall::Time => {
                    trace!("Time called; lying about the time");
                    proc.time_return()?;
                    stack.push(procid.clone());
                }
                Syscall::Upcall(n) => {
                    match n {
                        0 => {
                            // detect tracing
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            stack.push(procid.clone());
                        }
                        1 => {
                            // annotate timeout
                            let regs = proc.get_registers()?;
                            let ty = proc.read_string(regs.rdi)?;
                            trace!("Process {} setting timeout type to {}", proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.send_tcp_message(response)?;
                            self.new_timeout(procid.clone(), ty);
                            stack.push(procid.clone());
                        }
                        2 => {
                            // annotate message
                            let regs = proc.get_registers()?;
                            let ty = proc.read_string(regs.rdi)?;
                            trace!("Process {} setting message type to {}", proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.send_tcp_message(response)?;
                            self.new_message(ty);
                            stack.push(procid.clone());
                        }
                        3 => {
                            // annotate state
                            proc.stop_syscall()?;
                            self.annotate_state_procs
                                .insert(procid.parent_process(), procid.clone());
                            // we're going to block until we're needed
                        }
                        10 => {
                            // int field
                            let regs = proc.get_registers()?;
                            let path = proc.read_string(regs.rdi)?;
                            let value = regs.rsi;
                            trace!("Process {} setting current.{} to {}", proc, path, value);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.write_object_field(procid.clone(), &path, json!(value))?;
                            stack.push(procid.clone());
                        }
                        11 => {
                            // str field
                            let regs = proc.get_registers()?;
                            let path = proc.read_string(regs.rdi)?;
                            let value = proc.read_string(regs.rsi)?;
                            trace!("Process {} setting current.{} to {}", proc, path, value);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.write_object_field(procid.clone(), &path, json!(value))?;
                            stack.push(procid.clone());
                        }
                        12 => {
                            // protobuf field
                            let regs = proc.get_registers()?;
                            let path = proc.read_string(regs.rdi)?;
                            let mut message_type = proc.read_string(regs.rsi)?;
                            // for some reason, protobuf wants message types prefixed with "."
                            message_type.insert_str(0, ".");
                            let protobuf_ptr = regs.rdx;
                            let protobuf_len = regs.r10 as usize;
                            let protobuf_data = proc.read_data(protobuf_ptr, protobuf_len)?;
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            if let Some(p_to_j) = &self.protobuf_to_json {
                                let json = p_to_j.to_json(
                                    &message_type,
                                    &mut BufReader::new(&protobuf_data[..]),
                                );
                                match json {
                                    Ok(json) => {
                                        trace!(
                                            "Process {} setting current.{} to {:?}",
                                            proc,
                                            path,
                                            json
                                        );
                                        self.write_object_field(procid.clone(), &path, json)?;
                                    }
                                    Err(_e) => {
                                        trace!("Error deserializing protobuf, skipping");
                                        self.write_object_field(
                                            procid.clone(),
                                            &path,
                                            json!("Protobuf error"),
                                        )?;
                                    }
                                }
                                stack.push(procid.clone());
                            } else {
                                bail!("No protobufs registered");
                            }
                        }
                        _ => bail!("Bad upcall {}", n),
                    }
                }
                _ => {
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
                }
            }
        }
        Ok(())
    }

    fn get_state(
        &mut self,
        procid: TracedProcessIdentifier,
        response: &mut data::Response,
    ) -> Result<(), Error> {
        if let Some(procid) = self.annotate_state_procs.remove(&procid) {
            self.current_state = Some(json!({}));
            let proc = self.procs.get_mut(&procid).expect("Bad procid");
            proc.wake_from_stopped_call(Syscall::Upcall(10))?;
            self.fill_response(procid.clone(), response)?;
            response.states = json!({procid.name.clone(): self.current_state.take().unwrap()});
        }
        Ok(())
    }

    fn kill_process(&mut self, procid: TracedProcessIdentifier) -> Result<(), Error> {
        let mut child_proc_ids = Vec::<TracedProcessIdentifier>::new();
        if let Some(proc) = self.procs.get(&procid) {
            // figure out how many children this process has
            for (other_proc_id, other_proc) in self.procs.iter() {
                if other_proc.tgid == proc.tgid {
                    child_proc_ids.push(other_proc_id.clone());
                }
            }
            // kill the process
            proc.kill(child_proc_ids.len())?;
        }
        self.procs.remove(&procid);
        for child_id in child_proc_ids.iter() {
            self.procs.remove(child_id);
        }
        Ok(())
    }

    fn kill_all_processes(&mut self) -> Result<(), Error> {
        let mut proc_ids = Vec::<TracedProcessIdentifier>::new();
        for (proc_id, proc) in self.procs.iter() {
            if proc.tgid == proc.tid {
                proc_ids.push(proc_id.clone());
            }
        }
        for proc_id in proc_ids.iter() {
            self.kill_process(proc_id.clone())?;
        }
        Ok(())
    }

    pub fn handle_start(
        &mut self,
        node: String,
        response: &mut data::Response,
    ) -> Result<(), Error> {
        if !self.nodes.contains_key(&node) {
            bail!("Got bad node name {} from server", node);
        }
        let procid = TracedProcessIdentifier::main_process(node.clone());
        // kill proc if it's already started
        // need to make sure old process dies before new process starts
        self.kill_process(procid.clone())?;
        let program = &self.nodes[&node];
        let proc = TracedProcess::new(node.clone(), program.to_string())?;
        self.procs.insert(procid.clone(), proc);
        self.fill_response(procid.clone(), response)?;
        self.send_tcp_message(response)?;
        self.get_state(procid.clone().parent_process(), response)?;
        Ok(())
    }

    pub fn handle_message(
        &mut self,
        message: data::Message,
        response: &mut data::Response,
    ) -> Result<(), Error> {
        let node = message.to;
        let raw = message.raw;
        let wire_message: WireMessage = serde_json::from_value(raw)?;
        // first, deliver a TCP message if necessary
        if let MessageData::TcpMessage(size) = &wire_message.data {
            trace!("Got TCP message of size {}", size);
            let channel: &mut TcpChannel = {
                match &wire_message.to {
                    SocketAddress::TcpStream(name, id) => {
                        self.tcp_channels.get_mut(&(name.to_string(), *id)).unwrap()
                    }
                    _ => bail!("unexpected address"),
                }
            };
            let mut buf = vec![0; *size];
            trace!("Reading from socket");
            channel.remote.as_ref().unwrap().read_exact(&mut buf)?;
            trace!("Writing to socket");
            channel.local.as_ref().unwrap().write_all(&buf)?;
            *channel.delivered.borrow_mut() += size;
        }
        let mut message_delivered = false;
        while !message_delivered {
            let wire_message = wire_message.clone();
            if let Some((procid, call)) = self.message_waiting_procs.remove(&wire_message.to) {
                let procid = procid.clone();
                let call = call.clone();
                if procid.name != node {
                    bail!(
                        "Message send to mismatched node ({} vs {})",
                        procid.name,
                        node
                    );
                }
                match call {
                    Syscall::EpollWait(_, _, _, _) => {
                        let ret = self.handle_epoll(
                            procid.clone(),
                            call.clone(),
                            HandleEpollReason::Message(wire_message.to.clone()),
                            response,
                        )?;
                        if let HandleEpollResult::Return(events_ptr, data, why) = ret {
                            let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                            proc.epoll_return(events_ptr, data, why)?;
                        } else {
                            bail!("delivered epoll message, failed to wake");
                        }
                        if let MessageData::TcpMessage(_) = &wire_message.data {
                            // we've delivered this message and alerted the receiver,
                            // so we're done
                            message_delivered = true;
                        }
                    }
                    _ => {
                        let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                        match wire_message.data {
                            MessageData::Data(data) => {
                                message_delivered = true;
                                proc.recvfrom_return(wire_message.from, data)?;
                            }
                            MessageData::TcpConnect(remote_counter) => {
                                message_delivered = true;
                                if let Syscall::Accept(_, _) = call {
                                    if let SocketAddress::IPV4(port) = wire_message.to {
                                        // start accepting, but don't wait for syscall to return
                                        let (addr_ptr, addr_len) = proc.accept_continue()?;
                                        // this call should return immediately, since proc is accepting
                                        let local =
                                            TcpStream::connect(("localhost", port)).unwrap();
                                        let counter = proc.next_counter();
                                        let channel = {
                                            let remote_channel = self
                                                .tcp_channels
                                                .get_mut(&(message.from.clone(), remote_counter))
                                                .unwrap();
                                            remote_channel.remote =
                                                Some(local.try_clone().unwrap());
                                            remote_channel.remote_addr =
                                                Some(SocketAddress::TcpStream(
                                                    procid.name.clone(),
                                                    counter,
                                                ));
                                            remote_channel.reverse(SocketAddress::TcpStream(
                                                message.from.clone(),
                                                remote_counter,
                                            ))
                                        };
                                        self.tcp_channels
                                            .insert((procid.name.clone(), counter), channel);

                                        // send acknowledgment message
                                        let local_addr =
                                            SocketAddress::TcpStream(procid.name.clone(), counter);
                                        let raw = WireMessage {
                                            from: Some(local_addr.clone()),
                                            to: SocketAddress::TcpStream(
                                                message.from.clone(),
                                                remote_counter,
                                            ),
                                            data: MessageData::TcpAck(procid.name.clone()),
                                        };
                                        let mut response_message = data::Message::new();
                                        response_message.from = procid.name.clone();
                                        response_message.to = message.from.clone();
                                        response_message.ty = "Tcp-Ack".to_string();
                                        response_message.raw = serde_json::to_value(&raw).unwrap();
                                        response.messages.push(response_message);
                                        self.address_to_name
                                            .insert(local_addr.clone(), message.from.clone());
                                        proc.accept_return(
                                            addr_ptr,
                                            addr_len,
                                            wire_message.from,
                                            local_addr,
                                        )?;
                                    } else {
                                        bail!("Unsupported address type");
                                    }
                                } else {
                                    bail!("Connect to socket that isn't accept()-ing");
                                }
                            }
                            MessageData::TcpAck(_remote_name) => {
                                message_delivered = true;
                                if let Syscall::Connect(fd, _, _) = call {
                                    match (wire_message.to, wire_message.from) {
                                        (
                                            SocketAddress::TcpStream(local_name, local_stream_id),
                                            Some(SocketAddress::TcpStream(
                                                remote_name,
                                                remote_stream_id,
                                            )),
                                        ) => {
                                            let local_channel_id = (local_name, local_stream_id);
                                            let remote_channel_id = (remote_name, remote_stream_id);
                                            let listener = {
                                                let local_channel = self
                                                    .tcp_channels
                                                    .get(&local_channel_id)
                                                    .unwrap();
                                                local_channel
                                                    .listener
                                                    .as_ref()
                                                    .unwrap()
                                                    .try_clone()
                                                    .unwrap()
                                            };
                                            //let remote_stream = self.tcp_channels.get_mut(&(remote_name, remote_stream_id)).unwrap();
                                            // the connecting process should connect to our listener
                                            //local_stream.listener = remote_stream.listener.clone();
                                            let port = listener.local_addr().unwrap().port();
                                            // have the connecting process connect to the listener
                                            proc.connect_continue(SocketAddress::IPV4(port))?;
                                            // this accept() should return immediately
                                            trace!(
                                                "Calling accept() on listener; port is {}",
                                                port
                                            );
                                            let stream: Rc<TcpStream> = listener.accept()?.0.into();
                                            // overwrite both local and remote streams
                                            // now that conn is established
                                            {
                                                let local_channel = self
                                                    .tcp_channels
                                                    .get_mut(&local_channel_id)
                                                    .unwrap();
                                                local_channel.local =
                                                    Some(stream.try_clone().unwrap());
                                            }
                                            {
                                                let remote_channel = self
                                                    .tcp_channels
                                                    .get_mut(&remote_channel_id)
                                                    .unwrap();
                                                remote_channel.remote =
                                                    Some(stream.try_clone().unwrap());
                                            }
                                            proc.connect_return(
                                                fd,
                                                SocketAddress::TcpStream(
                                                    procid.name.clone(),
                                                    local_stream_id,
                                                ),
                                            )?;
                                        }
                                        _ => bail!("Bad Tcp-Ack message"),
                                    }
                                } else {
                                    bail!("Ack to socket that isn't connect()-ing");
                                }
                            }
                            MessageData::TcpMessage(_len) => {
                                message_delivered = true;
                                // we've got a TCP message and a waiting receiver. We
                                // already delivered the message.
                                let to_addr = wire_message.to.clone();
                                let channel = {
                                    match &to_addr {
                                        SocketAddress::TcpStream(name, id) => {
                                            self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                                        }
                                        _ => bail!("unexpected address"),
                                    }
                                };
                                proc.run_until_syscall()?;
                                let ret = proc.get_syscall_return(call.clone())?;
                                trace!("Process {} got syscall return {:?}", proc, ret);
                                if let SyscallReturn::Success(value) = ret {
                                    *channel.delivered.borrow_mut() -= value as usize;
                                }
                            }
                        }
                    }
                }
                let procid = procid.clone();
                self.fill_response(procid.clone(), response)?;
                self.send_tcp_message(response)?;
                self.get_state(procid.clone().parent_process(), response)?;
            } else {
                warn!("Message without matching waiting process");
                message_delivered = true;
            }
        }
        Ok(())
    }

    pub fn handle_timeout(
        &mut self,
        timeout: data::Timeout,
        response: &mut data::Response,
    ) -> Result<(), Error> {
        // always clear timeout
        response.cleared_timeouts.push(timeout.clone());
        let node = timeout.to;
        let raw = timeout.raw;
        let wire_timeout: WireTimeout = serde_json::from_value(raw)?;
        let timeout_id = wire_timeout.timeout_id;
        if let Some((procid, call)) = self.timeout_waiting_procs.remove(&timeout_id) {
            let procid = procid.clone();
            if procid.name != node {
                bail!(
                    "Timeout sent to mismatched node ({}, {})",
                    procid.name,
                    node
                );
            }
            match call {
                Syscall::NanoSleep(_, _) => {
                    let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                    proc.clock.borrow_mut().ensure_gt(&wire_timeout.clock);
                    proc.wake_from_stopped_call(call.clone())?;
                    let procid = procid.clone();
                    self.fill_response(procid, response)?;
                }
                Syscall::EpollWait(_, _, _, _) => {
                    let ret = self.handle_epoll(
                        procid.clone(),
                        call.clone(),
                        HandleEpollReason::Timeout(timeout_id.clone()),
                        response,
                    )?;
                    match ret {
                        HandleEpollResult::Return(events_ptr, data, why) => {
                            let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                            proc.clock.borrow_mut().ensure_gt(&wire_timeout.clock);
                            proc.epoll_return(events_ptr, data, why)?;
                            let procid = procid.clone();
                            self.fill_response(procid, response)?;
                        }
                        HandleEpollResult::TimedOut => {
                            let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                            proc.clock.borrow_mut().ensure_gt(&wire_timeout.clock);
                            proc.epoll_timedout()?;
                            let procid = procid.clone();
                            self.fill_response(procid, response)?;
                        }
                        _ => bail!("delivered epoll message, failed to wake"),
                    }
                }
                Syscall::FutexWait(futex, _, _, _) => {
                    // this was a timed futex wait. we'll want to wake the
                    // process and remove it from the wait queue.
                    let futex = futex.clone();
                    {
                        let waiters = self.futexes.entry(futex).or_insert_with(|| VecDeque::new());
                        let index = waiters
                            .iter()
                            .position(|e| *e == (procid.clone(), call.clone()));
                        if let Some(index) = index {
                            waiters.remove(index);
                        } else {
                            bail!("timeout waking unknown waiter");
                        }
                    }
                    let proc = self.procs.get_mut(&procid.clone()).expect("Bad procid");
                    proc.clock.borrow_mut().ensure_gt(&wire_timeout.clock);
                    proc.wake_from_stopped_call_with_ret(-1 * libc::ETIMEDOUT)?;
                    let procid = procid.clone();
                    self.fill_response(procid, response)?;
                }
                _ => bail!("unexpected call {:?} receiving timeout"),
            }
            self.send_tcp_message(response)?;
            self.get_state(procid.clone().parent_process(), response)?;
            Ok(())
        } else {
            warn!("Timeout without matching waiting process");
            Ok(())
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Handlers {
    fn drop(&mut self) {
        self.kill_all_processes()
            .expect("Problem killing procs while dropping Handlers");
    }
}
