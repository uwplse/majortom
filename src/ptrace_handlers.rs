use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::CString;
use std::net::{TcpListener, TcpStream};
use nix::unistd::{Pid, fork, ForkResult,execv};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::socket::{AddressFamily, SockProtocol, SockType, sockaddr_storage, sockaddr_in, SockFlag};
use nix::sched::CloneFlags;
use nix::sys::epoll::{EpollOp, EpollFlags};
use libc::{user_regs_struct, epoll_event};
use std::mem::size_of;
use std::slice;
use failure::{ResultExt, Error};
use tempfile::{TempDir};
use std::rc::Rc;
use std::cell::RefCell;
use base64_serde::base64_serde_type;
use std::fmt;
use std::io::{Read,Write};
use crate::futex::{Futex,FutexCmd, FUTEX_BITSET_MATCH_ANY};

base64_serde_type!(Base64Standard, base64::STANDARD);

use crate::data;

#[derive(Debug, Clone, PartialEq)]
enum File {
    TcpSocket(Option<SocketAddress>),
    UDPSocket(Option<SocketAddress>),
    EpollFd(Vec<(i32, EpollFlags)>),
    TimerFd(bool, bool), // armed, repeating
    SignalFd,
    ReadFile(String),
    WriteFile(String),
    Special
}

#[derive(Debug)]
struct FileSystemSnapshot {
    dir: TempDir,
    files: HashMap<String, Option<String>>,
    files_to_restore: Vec<String>,
    filenumber: i32,
    directories: HashSet<String>
}

fn is_read_only(flags: i32) -> bool {
    (flags & libc::O_ACCMODE) == libc::O_RDONLY
}

struct TcpChannel {
    remote: Option<TcpStream>,
    listener: Option<TcpListener>,
    local: Option<TcpStream>,
    sent: Rc<RefCell<usize>>,
    received: Rc<RefCell<usize>>,
    delivered: Rc<RefCell<usize>>,
    remote_addr: Option<SocketAddress>
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
            remote_addr: None
        }
    }

    fn reverse(&self, addr: SocketAddress) -> Self {
        Self {
            remote: match self.local {
                None => None,
                Some(ref s) =>
                    Some(s.try_clone().unwrap())
            },
            listener: self.listener.as_ref().map(|s| s.try_clone().unwrap()),
            local: self.remote.as_ref().map(|s| s.try_clone().unwrap()),
            sent: self.received.clone(),
            received: self.sent.clone(),
            delivered: Rc::new(RefCell::new(0)),
            remote_addr: Some(addr)
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
            filenumber: 0
        })
    }

    fn snapshot_file(&mut self, filename: String) -> Result<(), Error> {
        if !self.files.contains_key(&filename) {
            let name = self.filenumber.to_string();
            self.filenumber += 1;
            let path = self.dir.path().join(name);
            if std::path::Path::new(&filename).exists() {
                std::fs::copy(&filename, &path)?;
                self.files.insert(filename, Some(path.to_str().unwrap().to_owned()));
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
                trace!("Directory {} doesn't exist and shouldn't--we're good",
                       directory);
            }
        }
        for file in self.files_to_restore.iter() {
            let snapshot = self.files.get(&file.clone()).unwrap();
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
                        trace!("{} doesn't exist and shouldn't--we're good",
                               file);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TracedProcess {
    tgid: Pid,
    tid: Pid,
    files: Rc<RefCell<HashMap<i32, File>>>,
    snapshot: Rc<RefCell<FileSystemSnapshot>>,
    counter: Rc<RefCell<u64>>
}

impl fmt::Display for TracedProcess {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.tgid == self.tid {
            write!(f, "TracedProcess({})", self.tgid)
        }
        else {
            write!(f, "TracedProcess({}/{})", self.tgid, self.tid)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TracedProcessIdentifier {
    name: String,
    tid: Option<Pid> // used only for child threads
}

impl TracedProcessIdentifier {
    fn main_process(name: String) -> Self {
        Self {name, tid: None}
    }

    fn child_process(&self, tid: Pid) -> Self {
        Self {name: self.name.clone(), tid: Some(tid)}
    }

    fn parent_process(&self) -> Self {
        Self {name: self.name.clone(), tid: None}
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TimeoutId {
    id: u64
}

impl TimeoutId {
    fn to_bytes(&self) -> Vec<u8> {
        let mut ret = Vec::new();
        ret.extend(&self.id.to_le_bytes());
        return ret;
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let mut id: u64 = 0;
        for (i, b) in bytes.iter().enumerate() {
            id += (*b as u64) << (i * 8);
        }
        Self {id}
    }
}
    
struct TimeoutIdGenerator {
    next_id: u64
}

impl TimeoutIdGenerator {
    fn new() -> Self {
        Self {next_id: 0}
    }

    fn next(&mut self) -> TimeoutId {
        let next = TimeoutId {id: self.next_id};
        self.next_id += 1;
        next
    }
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Clone)]
enum MessageData {
    TcpConnect(u64),
    TcpAck(String),
    #[serde(with = "Base64Standard")]
    Data(Vec<u8>),
    TcpMessage(usize)
}


#[derive(Serialize, Deserialize)]
struct WireMessage {
    from: Option<SocketAddress>,
    to: SocketAddress,
    data: MessageData
}

pub struct Handlers {
    nodes: HashMap<String, String>,
    procs: HashMap<TracedProcessIdentifier, TracedProcess>,
    message_waiting_procs: HashMap<SocketAddress, (TracedProcessIdentifier, Syscall)>,
    timeout_id_generator: TimeoutIdGenerator,
    timeout_waiting_procs: HashMap<TimeoutId, (TracedProcessIdentifier, Syscall)>,
    address_to_name: HashMap<SocketAddress, String>,
    tcp_channels: HashMap<(String, u64), TcpChannel>,
    current_timeout: Option<data::Timeout>,
    current_message: Option<data::Message>,
    current_state: Option<serde_json::Value>,
    annotate_state_procs: HashMap<TracedProcessIdentifier, TracedProcessIdentifier>,
    current_tcp_message: Option<(SocketAddress, usize)>,
    // futex -> waiters (if any)
    futexes: HashMap<u64, VecDeque<(TracedProcessIdentifier, Syscall)>>
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum SocketAddress {
    // for now, we only care about the port.
    IPV4(u16), IPV6(u16),
    // fake socket address for Tcp streams
    TcpStream(String, u64)
}

#[derive(Debug, Clone)]
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
    MUnmap,
    Close(i32, File),
    Read(i32, File),
    UDPSocket,
    TcpSocket,
    GetAddrInfoSocket,
    SpecialOp,
    Bind(i32, SocketAddress),
    Listen(i32, i32),
    Connect(i32, File, SocketAddress),
    Accept(i32, File),
    Write(i32, File),
    RecvFrom(i32, File, usize),
    SigProcMask,
    SigAction,
    NanoSleep,
    SendTo(i32, File, Option<SocketAddress>, Vec<u8>),
    SetTidAddress,
    SetRobustList,
    // Futex handling! There's one "Futex" syscall that does many different
    // things, so we have some fake Futex calls to disambiguate.
    FutexTest,
    FutexWait(u64, u32),
    FutexWake(u64, usize, u32),
    FutexCmpRequeue(u64, usize, u32, u64, u32),
    GetRLimit,
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
    GetTid,
    SysInfo,
    ReadLink,
    SetITimer,
    GetTime,
    IoCtl,
    FnCtl,
    Unlink(String),
    Symlink(String, String),
    Fsync,
    FLock,
    MSync,
    MInCore,
    GetDents,
    SchedYield,
    TimerFdCreate,
    SignalFd,
    EpollCreate,
    // EpollFlags must be set if op is add or mod
    EpollCtl(i32, EpollOp, i32, Option<EpollFlags>),
    Upcall(usize),
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SyscallReturn {
    Success(i64), Failure(i64)
}

impl TracedProcess {
    fn new(program: String) -> Result<Self, Error> {
        let args: Vec<&str> = program.split(" " ).collect();
        let program_name = args[0];
        let mut files = HashMap::new();
        //stdin, stdout, stderr
        for fd in 0..3 {
            files.insert(fd, File::Special);
        }
        let proc = match fork()? {
            ForkResult::Parent {child, ..} => {
                trace!("Started child with pid {}", child);
                Self {tgid: child, tid: child, files: Rc::new(RefCell::new(files)),
                      counter: Rc::new(RefCell::new(0)),
                      snapshot: Rc::new(RefCell::new(FileSystemSnapshot::new()?))}
            },
            ForkResult::Child => {
                ptrace::traceme().expect("couldn't call trace");
                let args_cstring: Vec<CString> = args.into_iter().map(
                    |s| CString::new(s).unwrap()).collect();
                execv(&CString::new(program_name).unwrap(), &args_cstring)
                    .expect("couldn't exec");
                unreachable!();
            },
        };
        proc.wait_for_process_start()?;
        let options = ptrace::Options::PTRACE_O_TRACECLONE
            |ptrace::Options::PTRACE_O_TRACESYSGOOD
            |ptrace::Options::PTRACE_O_TRACEFORK
            |ptrace::Options::PTRACE_O_TRACEVFORK;
        ptrace::setoptions(proc.tid, options)?;
        Ok(proc)
    }

    fn next_counter(&self) -> u64 {
        *self.counter.borrow_mut() += 1;
        *self.counter.borrow()
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
                _ => bail!("Unexpected wait status after killing process: {:?}",
                           status)
            }
        }
        self.snapshot.borrow().restore_snapshot().context("Restoring snapshot")?;
        Ok(())
    }

    fn wait_for_process_start(&self) -> Result<(), Error> {
        trace!("waiting for child proc");
        let status = self.wait_status()?;
        match status {
            WaitStatus::Stopped(pid, _) if pid == self.tid => (),
            _ => bail!("Got bad status when waiting for child: {:?}", status)
        };
        Ok(())
    }

    fn wait_status(&self) -> Result<WaitStatus, Error> {
        use nix::sys::signal::Signal;
        loop {
            let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))?;
            match status {
                WaitStatus::Stopped(pid, signal) if
                    (signal == Signal::SIGWINCH ||
                     signal == Signal::SIGPROF) => {
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
            _ => bail!("Bad status when trying to get clone info: {:?}", status)
        }
        let child = Pid::from_raw(ptrace::getevent(self.tid)? as i32);
        let proc = Self {tgid: self.tgid, tid: child, files: self.files.clone(),
                         counter: Rc::clone(&self.counter),
                         snapshot: Rc::clone(&self.snapshot)};
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
        }
        else {
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
        let mut buf : [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let mut bytes : Vec<u8> = Vec::with_capacity(len);
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
                trace!("Read {:?} ({:?}) from process memory at {:?}", buf, raw, addr);
            }
            bytes.push(buf[i % size_of::<libc::c_long>()]);
            // addr incremented once for each *byte* read
        }
        trace!("read bytes {:?}", bytes);
        Ok(bytes)
    }

    fn read_string(&self, addr: u64) -> Result<String, Error> {
        let mut buf : libc::c_long;
        let mut bytes : Vec<u8> = Vec::new();
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

    unsafe fn read<T>(&self, addr: u64) -> Result<T, Error> where T: Copy {
        let mut buf : [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let mut bytes : Vec<u8> = Vec::new();
        let total = size_of::<T>();
        for i in 0..total {
            if i % size_of::<libc::c_long>() == 0 {
                buf = ptrace::read(self.tid, (addr + (i as u64)) as ptrace::AddressType)?.to_ne_bytes();
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
        let mut buf : [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let length = data.len();
        trace!("Going to write {:?} bytes into process memory at {:?}", length, addr);
        trace!("Writing {:?}", data);
        for (i, b) in data.iter().enumerate() {
            buf[i % size_of::<libc::c_long>()] = *b;
            if ((i + 1) % size_of::<libc::c_long>() == 0) ||
                i + 1 == length {
                    let word = u64::from_ne_bytes(buf);
                    trace!("Writing {:?} ({:?}) to process memory at {:?}", buf, word, addr);
                    let index = (i / size_of::<libc::c_long>()) * size_of::<libc::c_long>();
                    ptrace::write(self.tid, (addr + (index as u64)) as ptrace::AddressType,
                                  word as *mut libc::c_void)?;
            }
            // exit early if we're not iterating over whole vector
            if i + 1 == length {
                break;
            }
        }
        Ok(length)
    }

    unsafe fn write<T>(&self, addr: u64, t: T) -> Result<(), Error> where T: Copy {
        trace!("size_of(T) is {:?} bytes", size_of::<T>());
        let p: *const T = &t;     // the same operator is used as with references
        let p: *const u8 = p as *const u8;  // convert between pointer types
        let s: &[u8] = slice::from_raw_parts(p, size_of::<T>());
        self.write_data(addr, s.into())?;
        Ok(())
    }
    

    fn write_socket_address(&self, addr_ptr: u64, addrlen: usize,
                            addr: Option<SocketAddress>)
                            -> Result<(), Error> {
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
                        sin_addr: libc::in_addr {
                            s_addr: localhost
                        },
                        sin_zero: [0; 8]
                    };
                    unsafe {
                        self.write(addr_ptr, sa)?;
                    }
                }
                _ => bail!("attempt to write bad socket address")
            }
        }
        Ok(())
    }
    
    fn get_syscall(&self) -> Result<Syscall, Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let call_number = regs.orig_rax;
        let call = match call_number {
            0 => { //read()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Read(fd, file.clone()))
                } else {
                    bail!("read() called on unknown file")
                }
            },
            1 => { //write()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("write() called on unknown file")
                }
            }
            2 => { //open()
                let s = self.read_string(regs.rdi)?;
                let flags = regs.rsi as i32;
                if !is_read_only(flags) {
                    // snapshot file here: even though the open might not
                    // succeed, if it does it could create or truncate the file
                    self.snapshot.borrow_mut().snapshot_file(s.clone())?;
                }
                Ok(Syscall::Open(s, flags))
            }
            3 => { //close()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Close(fd, file.clone()))
                } else {
                    bail!("close() called on unknown file")
                }
            }
            4 => Ok(Syscall::Stat),
            5 => { //fstat()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Fstat(fd, file.clone()))
                } else {
                    bail!("fstat() called on unknown file")
                }
            },
            8 => Ok(Syscall::LSeek),
            9 => { // mmap(), only supported for global files for now
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
            },
            10 => Ok(Syscall::MProtect),
            11 => Ok(Syscall::MUnmap),
            12 => Ok(Syscall::Brk),
            // TODO: figure out if I actually need to deal with signals
            13 => Ok(Syscall::SigAction),
            14 => Ok(Syscall::SigProcMask),
            16 => Ok(Syscall::IoCtl),
            20 => { //writev()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("writev() called on unknown file")
                }
            }
            
            21 => { // access()
                let s = self.read_string(regs.rdi)?;
                Ok(Syscall::Access(s))
            },
            24 => Ok(Syscall::SchedYield),
            26 => Ok(Syscall::MSync),
            27 => Ok(Syscall::MInCore),
            32 => { // dup()
                let fd = regs.rdi as i32;
                Ok(Syscall::Dup(fd))
            }
            35 => Ok(Syscall::NanoSleep),
            38 => { //setitimer
                // Currently we only allow programs to set the
                // profiling timer, which we ignore.
                let which = regs.rdi as i32;
                if which == libc::ITIMER_PROF {
                    Ok(Syscall::SetITimer)
                } else {
                    bail!("Unsupported ITimer {}", which);
                }
            }
            41 => { // socket()
                let socket_family = regs.rdi as i32;
                let socket_type_and_flags = regs.rsi as i32;
                let socket_type = socket_type_and_flags & !(SockFlag::all().bits());
                let socket_protocol = regs.rdx as i32;
                // ensure this is a supported socket type
                if (socket_family == AddressFamily::Inet as i32 ||
                    socket_family == AddressFamily::Inet6 as i32) &&
                    (socket_type == SockType::Datagram as i32 ||
                     socket_protocol == SockProtocol::Udp as i32) {
                        Ok(Syscall::UDPSocket)
                    }
                else if (socket_family == AddressFamily::Inet as i32 ||
                    socket_family == AddressFamily::Inet6 as i32) &&
                    (socket_type == SockType::Stream as i32 ||
                     socket_protocol == SockProtocol::Tcp as i32) {
                        Ok(Syscall::TcpSocket)
                    }
                // special-case wacky getaddrinfo() sockets
                else if (socket_family == 16 &&
                         socket_type == 3 &&
                         socket_protocol == 0) ||
                    (socket_family == 1 &&
                         socket_type == 1 &&
                         socket_protocol == 0)
                {
                    Ok(Syscall::GetAddrInfoSocket)
                }
                else {
                    trace!("AF_INET={}, AF_INET6={}, SOCK_STREAM={}",
                           AddressFamily::Inet as i32,
                           AddressFamily::Inet6 as i32,
                           SockType::Stream as i32);
                    bail!("Unsupported socket({}, {}, {})",
                           socket_family, socket_type, socket_protocol);
                }
            },
            42 => { // connect()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    match sock {
                        File::TcpSocket(_) => {
                            let socket_address = self.read_socket_address(regs.rsi, regs.rdx as usize)?;
                            Ok(Syscall::Connect(fd, sock.clone(), socket_address))
                        }
                        File::Special => Ok(Syscall::SpecialOp),
                        _ => bail!("connect() called on bad file {:?}", sock)
                    }
                } else {
                    bail!("connect() called on unknown file");
                }
            },
            43 => { // accept()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Accept(fd, sock.clone()))
                } else {
                    bail!("accept() called on unknown file")
                }
            },
            44 => { // sendto()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    if sock == &File::Special {
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
            45 => { // recvfrom()
                let fd = regs.rdi as i32;
                let size = regs.rdx as usize;
                if let Some(sock) = self.files.borrow().get(&fd) {
                    Ok(Syscall::RecvFrom(fd, sock.clone(), size))
                } else {
                    bail!("recvfrom() called on unknown file")
                }
            }
            47 => { // recvmsg (only supported on special socks for now)
                let fd = regs.rdi as i32;
                if self.files.borrow().get(&fd) == Some(&File::Special) {
                    Ok(Syscall::SpecialOp)
                } else {
                    bail!("recvmsg not yet supported");
                }
            }
            49 => { // bind()
                let fd = regs.rdi as i32;
                if self.files.borrow().get(&fd) == Some(&File::Special) {
                    Ok(Syscall::SpecialOp)
                } else {
                    let socket_address = self.read_socket_address(regs.rsi, regs.rdx as usize)?;
                    Ok(Syscall::Bind(fd, socket_address))
                }
            },
            50 => { // listen()
                let fd = regs.rdi as i32;
                let backlog = regs.rsi as i32;
                Ok(Syscall::Listen(fd, backlog))
            },
            51 => { // getsockname()
                Ok(Syscall::GetSockName)
            }
            52 => { // getpeername()
                Ok(Syscall::GetPeerName)
            }
            54 => { // setsockopt()
                let fd = regs.rdi as i32;
                let level = regs.rsi as i32;
                let opt = regs.rdx as i32;
                Ok(Syscall::SetSockOpt(fd, level, opt))
            },
            56 => { // clone()
                let flags = CloneFlags::from_bits(regs.rdi as i32)
                    .ok_or(format_err!("Invalid clone() flags"))?;
                Ok(Syscall::Clone(flags))
            },
            63 => { // uname()
                Ok(Syscall::Uname)
            }
            72 => Ok(Syscall::FnCtl),
            73 => Ok(Syscall::FLock),
            74 => Ok(Syscall::Fsync),
            78 => Ok(Syscall::GetDents),
            83 => { // mkdir()
                let path = self.read_string(regs.rdi)?;
                Ok(Syscall::MkDir(path))
            }
            87 => { // unlink
                let path = self.read_string(regs.rdi)?;
                self.snapshot.borrow_mut().snapshot_file(path.clone())?;
                Ok(Syscall::Unlink(path))
            }
            88 => { // symlink
                let src_path = self.read_string(regs.rdi)?;
                let dst_path = self.read_string(regs.rsi)?;
                let mut snapshot = self.snapshot.borrow_mut();
                snapshot.snapshot_file(src_path.clone())?;
                snapshot.snapshot_file(dst_path.clone())?;
                Ok(Syscall::Symlink(src_path, dst_path))
            }
            89 => { // readlink()
                Ok(Syscall::ReadLink)
            }
            97 => Ok(Syscall::GetRLimit),
            99 => { // sysinfo()
                Ok(Syscall::SysInfo)
            }
            131 => Ok(Syscall::SigAltStack),
            158 => Ok(Syscall::ArchPrctl),
            186 => Ok(Syscall::GetTid),
            // Futexes!
            202 => {
                let word = regs.rdi as u64;
                let op = regs.rsi as i32;
                let val = regs.rdx as u32;
                let uaddr2 = regs.r8 as u64;
                let val3 = regs.r9 as u32;
                let time_ptr = regs.r10 as u64;
                let futex = Futex::from_i32(op);
                if let Some(futex) = futex {
                    match futex {
                        // TODO: worry about private futexes?
                        Futex {cmd: FutexCmd::WaitBitset,
                               private: true,
                               realtime: true} =>
                            Ok(Syscall::FutexTest),
                        Futex {cmd: FutexCmd::Wait,
                               private: _,
                               realtime: _} => {
                            if time_ptr != 0 {
                                bail!("Timed futex waits not yet supported");
                            }
                            Ok(Syscall::FutexWait(word, FUTEX_BITSET_MATCH_ANY))
                        }
                        Futex {cmd: FutexCmd::WaitBitset,
                               private: true,
                               realtime: false} => {
                            trace!("Waitbitset on {}, {}", word, val3);
                            Ok(Syscall::FutexWait(word, val3))
                        }
                        Futex {cmd: FutexCmd::Wake,
                               private: _,
                               realtime: _} => {
                            Ok(Syscall::FutexWake(word, val as usize, FUTEX_BITSET_MATCH_ANY))
                        }
                        Futex {cmd: FutexCmd::WakeBitset,
                               private: _,
                               realtime: _} => {
                            Ok(Syscall::FutexWake(word, val as usize, val3))
                        }
                        Futex {cmd: FutexCmd::CmpRequeue,
                               private: _,
                               realtime: _} => {
                            let val2 = time_ptr as u32; /* seriously */
                            unimplemented!()
                        }
                        _ => bail!("Bad futex op {:?}", futex)
                    }
                } else {
                    bail!("Bad futex op {}", op)
                }
            }
            203 => Ok(Syscall::SchedSetAffinity),
            204 => Ok(Syscall::SchedGetAffinity),
            228 => { // clock_gettime
                // For now, we're just going to let these go through.
                Ok(Syscall::GetTime)
            }
            218 => Ok(Syscall::SetTidAddress),
            233 => { // epoll_ctl
                let epfd = regs.rdi as i32;
                let op: EpollOp = match regs.rsi as i32 {
                    x if x == EpollOp::EpollCtlAdd as i32 => EpollOp::EpollCtlAdd,
                    x if x == EpollOp::EpollCtlDel as i32 => EpollOp::EpollCtlDel,
                    x if x == EpollOp::EpollCtlMod as i32 => EpollOp::EpollCtlMod,
                    _ => bail!("Bad epoll op")
                };
                let fd = regs.rdx as i32;
                let flags = {
                    if regs.r10 == 0 {
                        if op == EpollOp::EpollCtlDel {
                            None
                        } else {
                            bail!("Epoll called with null events");
                        }
                    } else {
                        let event_struct: epoll_event = unsafe {
                            self.read(regs.r10)?
                        };
                        Some(EpollFlags::from_bits(event_struct.events as i32).unwrap())
                    }
                };
                Ok(Syscall::EpollCtl(epfd, op, fd, flags))
            }
            257 => { // openat()
                let fd = regs.rdi as i32;
                // TODO: factor out this relative path logic (used in mkdirat() too)
                let path = {
                    let relative = self.read_string(regs.rsi)?;
                    let mut path = std::path::PathBuf::new();
                    match self.files.borrow().get(&fd) {
                        Some(File::ReadFile(dirpath)) => path.push(dirpath.clone()),
                        file => bail!("mkdirat called on bad file {:?}", file)
                    };
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
            258 => { // mkdirat()
                let fd = regs.rdi as i32;
                let path = {
                    let relative = self.read_string(regs.rsi)?;
                    let mut path = std::path::PathBuf::new();
                    match self.files.borrow().get(&fd) {
                        Some(File::ReadFile(dirpath)) => path.push(dirpath.clone()),
                        file => bail!("mkdirat called on bad file {:?}", file)
                    };
                    path.push(relative);
                    path.to_str().unwrap().to_string()
                };
                Ok(Syscall::MkDir(path))
            }
            273 => Ok(Syscall::SetRobustList),
            283 => { // timerfd_create
                Ok(Syscall::TimerFdCreate)
            }
            285 => { // fallocate()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.borrow().get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("fallocate() called on unknown file")
                }
            }
            289 => { // signalfd
                Ok(Syscall::SignalFd)
            }
            291 => { // epoll_create1
                Ok(Syscall::EpollCreate) // ignore flags for now
            }
            // upcalls from application
            x if x >= 5000 => Ok(Syscall::Upcall((x - 5000) as usize)),
            _ => bail!("Unsupported system call {} called by process {:?}",
                        call_number, self)
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
                let file =
                    if (flags & libc::O_ACCMODE) == libc::O_RDONLY {
                        // this is a read-only file, so we don't need to worry too
                        // much about it
                        File::ReadFile(filename)
                    } else {
                        // this file might be written too, so we need to save a
                        // copy of it
                        self.snapshot.borrow_mut().mark_for_restoration(filename.clone());
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
            (Syscall::Close(fd, _), SyscallReturn::Success(_)) => {
                trace!("Removing file {} from proc {:?}", fd, self);
                self.files.borrow_mut().remove(&fd);
            }
            (Syscall::Unlink(path), SyscallReturn::Success(_)) => {
                trace!("Marking {} for restoration (unlinked)", path);
                self.snapshot.borrow_mut().mark_for_restoration(path.clone());
            }
            (Syscall::Symlink(src_path, dst_path), SyscallReturn::Success(_)) => {
                trace!("Marking {} and {} for restoration (symlink)", src_path, dst_path);
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
                let file = File::TimerFd(false, false);
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::SignalFd, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::SignalFd;
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::EpollCreate, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::EpollFd(Vec::new());
                self.files.borrow_mut().insert(fd, file);
            }
            (Syscall::EpollCtl(epfd, op, fd, flags), SyscallReturn::Success(_)) => {
                use EpollOp::*;
                match self.files.borrow_mut().get_mut(&epfd) {
                    Some(File::EpollFd(fds)) => {
                        match op {
                            EpollCtlAdd => {
                                fds.push((fd, flags.unwrap()))
                            }
                            EpollCtlMod => {
                                for entry in fds.iter_mut() {
                                    if entry.0 == fd {
                                        entry.1 = flags.unwrap()
                                    }
                                }
                            }
                            EpollCtlDel => {
                                let index = fds.iter().position(|e| e.0 == fd).unwrap();
                                fds.remove(index);

                            }
                        }
                    }
                    file => bail!("epoll_ctl on bad file {:?}", file)
                }
            }
            (Syscall::MkDir(path), SyscallReturn::Success(_)) => {
                // we successfully made a directory, so we're going to want to
                // remove it
                self.snapshot.borrow_mut().snapshot_directory(path);
            }
            _ => ()
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
            Syscall::SendTo(_, _, _, data) =>
                data.len() as u64,
            Syscall::Upcall(_) => 42 as u64,
            _ => 0
        };
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
    fn recvfrom_return(&self, addr: Option<SocketAddress>, data: Vec<u8>)
                       -> Result<(), Error> {
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

    fn accept_return(&mut self, addr_ptr: u64, addr_len: usize, addr: Option<SocketAddress>,
                     local_addr: SocketAddress) -> Result<(), Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let sys_ret = regs.rax as i64;
        if sys_ret < 0 {
            bail!("accept() failed");
        }
        let fd = sys_ret as i32;
        self.files.borrow_mut().insert(fd, File::TcpSocket(Some(local_addr)));
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

    fn continue_return(&mut self, fd: i32, addr: SocketAddress) -> Result<(), Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let sys_ret = regs.rax as i64;
        if sys_ret < 0 {
            bail!("continue() failed");
        }
        self.files.borrow_mut().insert(fd, File::TcpSocket(Some(addr)));
        Ok(())
    }

}



impl Handlers {
    pub fn new(nodes: HashMap<String, String>) -> Self {
        Self {nodes, procs: HashMap::new(), message_waiting_procs: HashMap::new(),
              timeout_id_generator: TimeoutIdGenerator::new(),
              timeout_waiting_procs: HashMap::new(),
              annotate_state_procs: HashMap::new(),
              address_to_name: HashMap::new(),
              tcp_channels: HashMap::new(),
              current_timeout: None,
              current_message: None,
              current_state: None,
              current_tcp_message: None,
              futexes: HashMap::new()
        }
    }

    pub fn servers(&self) -> Vec<&str> {
        let mut res = Vec::new();
        res.extend(self.nodes.keys().map(|s| s.as_str()));
        res
    }

    fn new_timeout(&mut self, ty: String) {
        let mut timeout = data::Timeout::new();
        timeout.ty = ty;
        self.current_timeout = Some(timeout);
    }

    fn new_message(&mut self, ty: String) {
        let mut message = data::Message::new();
        message.ty = ty;
        self.current_message = Some(message);
    }
    
    fn current_body(&mut self) ->
        Result<&mut serde_json::Value, Error> {
        match self.current_timeout.as_mut() {
            Some(timeout) => return Ok(&mut timeout.body),
            None => ()
        }
        match self.current_message.as_mut() {
            Some(message) => return Ok(&mut message.body),
            None => ()
        }
        match self.current_state.as_mut() {
            Some(state) => return Ok(state),
            None => ()
        }
        bail!("No current body");
    }

    fn get_current_timeout(&mut self, node: String, timeout_id: TimeoutId) -> data::Timeout {
        let mut timeout = self.current_timeout.take().unwrap_or_else(|| data::Timeout::new());
        timeout.raw.extend(timeout_id.to_bytes());
        timeout.to = node;
        timeout
    }

    fn get_current_message(&mut self, from: String, to: String, data: serde_json::Value)
                           -> data::Message {
        let mut message = self.current_message.take().unwrap_or_else(|| data::Message::new());
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
                        data: MessageData::TcpMessage(bytes)
                    };
                    let data = serde_json::to_value(&raw).unwrap();
                    let message = self.get_current_message(from.to_string(), to.to_string(), data);
                    response.messages.push(message);
                }
                _ => bail!("Bad TCP address")
            }
        }
        Ok(())
    }
    
    /// Fills the response from any non-blocking syscalls made by proc procid
    ///
    /// Should be called after any outstanding syscalls have been
    /// processed--i.e., a syscall exit (or process start) is the most recent
    /// event
    fn fill_response(&mut self, procid: TracedProcessIdentifier, response: &mut data::Response)
                     -> Result<(), Error> {
        let mut stack = Vec::<TracedProcessIdentifier>::new();
        stack.push(procid);
        // this is hacky
        while let Some(procid) = stack.pop() {
            trace!("Filling response from process {:?}", procid);
            let proc = self.procs.get_mut(&procid).expect(
                &format!("Bad process identifier {:?}", procid));
            proc.run_until_syscall()?;
            let call = proc.get_syscall()?;
            trace!("Process {} called Syscall {:?}", proc, call);
            // check for unsupported calls and panic if necessary
            match &call {
                Syscall::Read(_, file) => {
                    match file {
                        File::ReadFile(_) | File::WriteFile(_) | File::Special => (),
                        _ => bail!("Unsupported read of file {:?}", file)
                    }
                }
                Syscall::Write(_, file) => {
                    match file {
                        File::Special => (),
                        File::WriteFile(_) => (),
                        _ => bail!("Unsupported write to file {:?}", file)
                    }
                }
                Syscall::MMap(_, Some(file)) => {
                    match file {
                        File::ReadFile(_) => (),
                        File::WriteFile(_) => (),
                        _ => bail!("Unsupported mmap on file {:?}", file)
                    }
                },
                Syscall::RecvFrom(_, file, _) => {
                    match file {
                        File::UDPSocket(Some(_)) => (),
                        File::TcpSocket(Some(SocketAddress::TcpStream(_, _))) => (),
                        _ => bail!("Unsupported recvfrom on file {:?}", file)
                    }
                },
                Syscall::Accept(_, file) => {
                    match file {
                        File::TcpSocket(Some(_)) => (),
                        _ => bail!("Unsupported accept on file {:?}", file)
                    }
                }
                Syscall::SendTo(_, file, addr, _) => {
                    match (file, addr) {
                        (File::UDPSocket(_), Some(_)) => (),
                        (File::TcpSocket(Some(SocketAddress::TcpStream(_, _))), _) => (),
                        _ => bail!("Unsupported sendto on file {:?}", file)
                    }
                }
                Syscall::Connect(_, file, _) => {
                    match file {
                        File::TcpSocket(_) => (),
                        _ => bail!("Unsupported connect on file {:?}", file)
                    }
                }
                Syscall::SetSockOpt(_, level, opt) => {
                    match (*level, *opt) {
                        (libc::SOL_SOCKET, libc::SO_REUSEADDR) => (),
                        _ => bail!("Unsupported setsockopt: {}/{}", level, opt)
                    }
                }
                _ => ()
            }
            match &call {
                Syscall::RecvFrom(_, File::UDPSocket(Some(addr)), _) => {
                    proc.stop_syscall()?;
                    self.message_waiting_procs.insert(addr.clone(),
                                                      (procid.clone(), call.clone()));
                    // we're blocking, so we're done here
                }
                Syscall::RecvFrom(_, File::TcpSocket(Some(to_addr)), _size) => {
                    let to_addr = to_addr.clone();
                    let channel = {
                        match &to_addr {
                            SocketAddress::TcpStream(name, id) => {
                                self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                            }
                            _ => bail!("unexpected address")
                        }
                    };
                    let delivered = *channel.delivered.borrow();
                    if delivered > 0 {
                        proc.run_until_syscall()?;
                        let ret = proc.get_syscall_return(call)?;
                        trace!("Process {} got syscall return {:?}", proc, ret);
                        if let SyscallReturn::Success(value) = ret {
                            *channel.delivered.borrow_mut() -= value as usize;
                        }
                        stack.push(procid.clone());
                    } else {
                        self.message_waiting_procs.insert(to_addr.clone(),
                                                          (procid.clone(), call.clone()));
                    }
                }
                Syscall::Connect(_fd, File::TcpSocket(from_addr), to_addr) => {
                    // don't stop the process
                    if let Some(to) = self.address_to_name.get(&to_addr) {
                        let counter = proc.next_counter();
                        let listener = TcpListener::bind(("localhost", 0)).unwrap();
                        let mut tcp_channel = TcpChannel::new();
                        tcp_channel.listener = Some(listener);
                        self.tcp_channels.insert((procid.name.clone(), counter), tcp_channel);
                        let raw = WireMessage {from: from_addr.clone(),
                                               to: to_addr.clone(),
                                               data: MessageData::TcpConnect(counter)};
                        let mut message = data::Message::new();
                        message.from = procid.name.clone();
                        message.to = to.clone();
                        message.ty = "Tcp-Connect".to_string();
                        message.raw = serde_json::to_value(&raw).unwrap();
                        response.messages.push(message);
                        let channel_addr = SocketAddress::TcpStream(procid.name.clone(), counter);
                        self.address_to_name.insert(channel_addr.clone(), to.clone());
                        self.message_waiting_procs.insert(channel_addr, (procid.clone(), call.clone()));
                        // we're blocking waiting for a response, so we're done here
                    }
                    else {
                        bail!("Connect to unknown address {:?}", to_addr);
                    }
                }
                Syscall::Accept(_, File::TcpSocket(Some(addr))) => {
                    // don't stop the process
                    self.message_waiting_procs.insert(addr.clone(),
                                                      (procid.clone(),
                                                       call.clone()));
                }
                Syscall::NanoSleep => {
                    proc.stop_syscall()?;
                    let timeout_id = self.timeout_id_generator.next();
                    self.timeout_waiting_procs.insert(timeout_id.clone(),
                                                      (procid.clone(), call.clone()));
                    let timeout = self.get_current_timeout(procid.name.clone(), timeout_id);
                    response.timeouts.push(timeout);
                    // we're blocking, so we're done here
                }
                // handle UDP send
                Syscall::SendTo(_, File::UDPSocket(from_addr), Some(to_addr), data) => {
                    proc.stop_syscall()?;
                    if let Some(to) = self.address_to_name.get(&to_addr) {
                        proc.wake_from_stopped_call(call.clone())?;
                        let raw = WireMessage {from: from_addr.clone(),
                                               to: to_addr.clone(),
                                               data: MessageData::Data(data.clone())};
                        let message = self.get_current_message(procid.name.clone(),
                                                               to.clone(),
                                                               serde_json::to_value(&raw).unwrap());
                        response.messages.push(message);
                        // don't execute ordinary syscall return handling
                        // keep filling response
                        stack.push(procid.clone());
                    } else {
                        bail!("Send to unknown address {:?}", to_addr);
                    }
                }
                // handle TCP send
                Syscall::SendTo(_,
                                File::TcpSocket(Some(to_addr)),
                                _, data) => {
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
                            _ => bail!("unexpected address")
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
                Syscall::Clone(_) => { // TODO: handle different clone flags differently?
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
                    self.address_to_name.insert(addr.clone(), procid.name.clone());
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
                }
                Syscall::FutexWait(futex, _) => {
                    // Add us to the queue for this futex
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let waiters = self.futexes.entry(futex).or_insert_with(
                        || VecDeque::new());
                    trace!("Proc {:?} going on queue for futex {} with call {:?}",
                           procid.clone(), futex, call);
                    waiters.push_back((procid.clone(), call.clone()));
                    // We're done here--we're waiting to be awoken
                }
                Syscall::FutexWake(futex, max_wakes, bitset) => {
                    proc.stop_syscall()?;
                    let futex = *futex;
                    let max_wakes = *max_wakes;
                    let bitset = *bitset;
                    // let's see if a process is actually waiting on this futex
                    let waiters = self.futexes.entry(futex).or_insert_with(
                        || VecDeque::new());
                    
                    /* 
                    We want to wake as many processes as we can, such that:
                    1. We wake at most *max_wakes* processes
                    2. We wake only processes matching the bitset
                     */
                    let mut wakes = Vec::<(TracedProcessIdentifier, Syscall)>::new();
                    let mut i = 0;
                    while i < waiters.len() && wakes.len() < max_wakes {
                        match waiters[i].1 {
                            Syscall::FutexWait(_, waiter_bitset)
                                if bitset & waiter_bitset != 0 => {
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
                        let waiter = self.procs.get_mut(&waiter_id).expect(
                            &format!("Bad process identifier {:?}", waiter_id));
                        waiter.wake_from_stopped_call(call)?;
                        stack.push(waiter_id.clone());
                    }
                }
                Syscall::Upcall(n) => {
                    match n {
                        0 => { // detect tracing
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            stack.push(procid.clone());
                        }
                        1 => { // annotate timeout
                            let regs = proc.get_registers()?;
                            let ty = proc.read_string(regs.rdi)?;
                            trace!("Process {} setting timeout type to {}",
                                   proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.send_tcp_message(response)?;
                            self.new_timeout(ty);
                            stack.push(procid.clone());
                        }
                        2 => { // annotate message
                            let regs = proc.get_registers()?;
                            let ty = proc.read_string(regs.rdi)?;
                            trace!("Process {} setting message type to {}",
                                   proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.send_tcp_message(response)?;
                            self.new_message(ty);
                            stack.push(procid.clone());
                        }
                        3 => { // annotate state
                            proc.stop_syscall()?;
                            self.annotate_state_procs.insert(procid.parent_process(), procid.clone());
                            // we're going to block until we're needed
                        }
                        10 => { // int field
                            let regs = proc.get_registers()?;
                            let path = proc.read_string(regs.rdi)?;
                            let value = regs.rsi;
                            trace!("Process {} setting current.{} to {}",
                                   proc, path, value);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            let mut obj = self.current_body()?
                                .as_object_mut().ok_or(format_err!("Bad json object"))?;
                            let mut fields: Vec<&str> = path.rsplit(".").collect();
                            while let Some(field) = fields.pop() {
                                if fields.is_empty() {
                                    obj.insert(field.to_string(), json!(value));
                                }
                                else {
                                    if !obj.get(field).map_or(false, |x| x.is_object()) {
                                        obj.insert(field.to_string(), json!({}));
                                    }
                                    obj = obj[field].as_object_mut().expect("Bad json object");
                                }
                            }
                            stack.push(procid.clone());
                        }
                        11 => { // str field
                            let regs = proc.get_registers()?;
                            let path = proc.read_string(regs.rdi)?;
                            let value = proc.read_string(regs.rsi)?;
                            trace!("Process {} setting current.{} to {}",
                                   proc, path, value);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            let mut obj = self.current_body()?
                                .as_object_mut().ok_or(format_err!("Bad json object"))?;
                            let mut fields: Vec<&str> = path.rsplit(".").collect();
                            while let Some(field) = fields.pop() {
                                if fields.is_empty() {
                                    obj.insert(field.to_string(), json!(value));
                                }
                                else {
                                    if !obj.get(field).map_or(false, |x| x.is_object()) {
                                        obj.insert(field.to_string(), json!({}));
                                    }
                                    obj = obj[field].as_object_mut().expect("Bad json object");
                                }
                            }
                            stack.push(procid.clone());
                        }
                        _ => bail!("Bad upcall {}", n)
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

    fn get_state(&mut self, procid: TracedProcessIdentifier, response: &mut data::Response) ->
        Result<(), Error> {
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
    
    pub fn handle_start(&mut self, node: String, response: &mut data::Response)
                        -> Result<(), Error> {
        if !self.nodes.contains_key(&node) {
            bail!("Got bad node name {} from server", node);
        }
        let procid = TracedProcessIdentifier::main_process(node.clone());
        // kill proc if it's already started
        // need to make sure old process dies before new process starts
        self.kill_process(procid.clone())?;
        let program = &self.nodes[&node];
        let proc = TracedProcess::new(program.to_string())?;
        self.procs.insert(procid.clone(), proc);
        self.fill_response(procid.clone(), response)?;
        self.send_tcp_message(response)?;
        self.get_state(procid.clone().parent_process(), response)?;
        Ok(())
    }

    pub fn handle_message(&mut self, message: data::Message, response: &mut data::Response)
                          -> Result<(), Error> {
        let node = message.to;
        let raw = message.raw;
        let wire_message : WireMessage = serde_json::from_value(raw)?;
        // first, deliver a TCP message if necessary
        if let MessageData::TcpMessage(size) = &wire_message.data {
            trace!("Got TCP message of size {}", size);
            let channel: &mut TcpChannel = {
                match &wire_message.to {
                    SocketAddress::TcpStream(name, id) => {
                        self.tcp_channels.get_mut(&(name.to_string(), *id)).unwrap()
                    }
                    _ => bail!("unexpected address")
                }
            };
            let mut buf = vec![0; *size];
            trace!("Reading from socket");
            channel.remote.as_ref().unwrap().read_exact(&mut buf)?;
            trace!("Writing to socket");
            channel.local.as_ref().unwrap().write_all(&buf)?;
            *channel.delivered.borrow_mut() += size;
        }
        if let Some((procid, call)) = self.message_waiting_procs.get(&wire_message.to) {
            if procid.name != node {
                bail!("Message send to mismatched node ({} vs {})", procid.name, node);
            }
            // for now assume call is a recvfrom()
            let proc = self.procs.get_mut(procid).expect("Bad procid");
            match wire_message.data {
                MessageData::Data(data) => {
                    proc.recvfrom_return(wire_message.from, data)?;
                }
                MessageData::TcpConnect(remote_counter) => {
                    if let Syscall::Accept(_, _) = call {
                        if let SocketAddress::IPV4(port) = wire_message.to {
                            // start accepting, but don't wait for syscall to return
                            let (addr_ptr, addr_len) = proc.accept_continue()?;
                            // this call should return immediately, since proc is accepting
                            let local = TcpStream::connect(("localhost", port)).unwrap();
                            let counter = proc.next_counter();
                            let channel = {
                                let remote_channel =
                                    self.tcp_channels.get_mut(&(message.from.clone(),
                                                                remote_counter)).unwrap();
                                remote_channel.remote = Some(local.try_clone().unwrap());
                                remote_channel.remote_addr = Some(SocketAddress::TcpStream(procid.name.clone(), counter));
                                remote_channel.reverse(SocketAddress::TcpStream(message.from.clone(), remote_counter))
                            };
                            self.tcp_channels.insert((procid.name.clone(), counter), channel);

                            // send acknowledgment message
                            let local_addr = SocketAddress::TcpStream(procid.name.clone(), counter);
                            let raw = WireMessage {from: Some(local_addr.clone()),
                                                   to: SocketAddress::TcpStream(message.from.clone(),
                                                                                remote_counter),
                                                   data: MessageData::TcpAck(procid.name.clone())};
                            let mut response_message = data::Message::new();
                            response_message.from = procid.name.clone();
                            response_message.to = message.from.clone();
                            response_message.ty = "Tcp-Ack".to_string();
                            response_message.raw = serde_json::to_value(&raw).unwrap();
                            response.messages.push(response_message);
                            self.address_to_name.insert(local_addr.clone(), message.from.clone());
                            proc.accept_return(addr_ptr, addr_len, wire_message.from, local_addr)?;
                        } else {
                            bail!("Unsupported address type");
                        }
                    } else {
                        bail!("Connect to socket that isn't accept()-ing");
                    }
                }
                MessageData::TcpAck(_remote_name) => {
                    if let Syscall::Connect(fd, _, _) =  call {
                        match (wire_message.to, wire_message.from) {
                            (SocketAddress::TcpStream(local_name, local_stream_id),
                             Some(SocketAddress::TcpStream(remote_name, remote_stream_id)))
                                => {
                                    let local_channel_id = (local_name,
                                                            local_stream_id);
                                    let remote_channel_id = (remote_name,
                                                             remote_stream_id);
                                    let listener = {
                                        let local_channel =
                                            self.tcp_channels.get(&local_channel_id).unwrap();
                                        local_channel.listener.as_ref().unwrap().try_clone().unwrap()
                                    };
                                    //let remote_stream = self.tcp_channels.get_mut(&(remote_name, remote_stream_id)).unwrap();
                                    // the connecting process should connect to our listener
                                    //local_stream.listener = remote_stream.listener.clone();
                                    let port = listener.local_addr().unwrap().port();
                                    // have the connecting process connect to the listener
                                    proc.connect_continue(SocketAddress::IPV4(port))?;
                                    // this accept() should return immediately
                                    trace!("Calling accept() on listener; port is {}", port);
                                    let stream: Rc<TcpStream> = listener.accept()?.0.into();
                                    // overwrite both local and remote streams
                                    // now that conn is established
                                    {
                                        let local_channel = self.tcp_channels.get_mut(
                                            &local_channel_id).unwrap();
                                        local_channel.local = Some(stream.try_clone().unwrap());
                                    }
                                    {
                                        let remote_channel = self.tcp_channels.get_mut(
                                            &remote_channel_id).unwrap();
                                        remote_channel.remote = Some(stream.try_clone().unwrap());
                                    }
                                    proc.continue_return(*fd,
                                                         SocketAddress::TcpStream(procid.name.clone(),
                                                                                  local_stream_id))?;
                                    
                                }
                            _ => bail!("Bad Tcp-Ack message")
                        }
                    } else {
                        bail!("Ack to socket that isn't connect()-ing");
                    }
                }
                MessageData::TcpMessage(_len) => {
                    // we've got a TCP message and a waiting receiver. We
                    // already delivered the message.
                    let to_addr = wire_message.to.clone();
                    let channel = {
                        match &to_addr {
                            SocketAddress::TcpStream(name, id) => {
                                self.tcp_channels.get(&(name.to_string(), *id)).unwrap()
                            }
                            _ => bail!("unexpected address")
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
            let procid = procid.clone();
            self.fill_response(procid.clone(), response)?;
            self.send_tcp_message(response)?;
            self.get_state(procid.clone().parent_process(), response)?;
        } else {
            trace!("Message to unknown recipient");
        }
        Ok(())
    }

    pub fn handle_timeout(&mut self, timeout: data::Timeout,
                          response: &mut data::Response)
                          -> Result<(), Error> {
        // always clear timeout
        response.cleared_timeouts.push(timeout.clone());
        let node = timeout.to;
        let raw = timeout.raw;
        let timeout_id = TimeoutId::from_bytes(&raw);
        if let Some((procid, call)) = self.timeout_waiting_procs.get(&timeout_id) {
            if procid.name != node {
                bail!("Timeout sent to mismatched node ({}, {})", procid.name, node);
            }
            let proc = self.procs.get_mut(procid).expect("Bad procid");
            proc.wake_from_stopped_call(call.clone())?;
            let procid = procid.clone();
            self.fill_response(procid.clone(), response)?;
            self.send_tcp_message(response)?;
            self.get_state(procid.parent_process(), response)?;
            Ok(())
        } else {
            bail!("Timeout to unknown recipient")
        }
    }
}

impl Drop for Handlers {
    fn drop(&mut self) {
        self.kill_all_processes()
            .expect("Problem killing procs while dropping Handlers");
    }
}
