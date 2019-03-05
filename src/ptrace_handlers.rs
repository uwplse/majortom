use std::collections::HashMap;
use std::ffi::CString;
use nix::unistd::{Pid, fork, ForkResult,execv};
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus, WaitPidFlag};
use nix::sys::signal::{kill, Signal};
use nix::sys::socket::{AddressFamily, SockProtocol, SockType, sockaddr_storage, sockaddr_in};
use nix::sched::CloneFlags;
use libc::user_regs_struct;
use bincode::{serialize, deserialize};
use std::mem::size_of;
use failure::Error;

use crate::data;

#[derive(Debug, Clone)]
enum File {
    UDPSocket(Option<SocketAddress>),
    GlobalFile(String),
//  LocalFile(String),
    Special
}

#[derive(Debug, Clone)]
struct TracedProcess {
    tgid: Pid,
    tid: Pid,
    files: HashMap<i32, File>,
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
        TimeoutId {id: self.next_id}
    }
}

#[derive(Serialize, Deserialize)]
struct WireMessage {
    from: Option<SocketAddress>,
    to: SocketAddress,
    data: Vec<u8>
}

pub struct Handlers {
    nodes: HashMap<String, String>,
    procs: HashMap<TracedProcessIdentifier, TracedProcess>,
    message_waiting_procs: HashMap<SocketAddress, (TracedProcessIdentifier, Syscall)>,
    timeout_id_generator: TimeoutIdGenerator,
    timeout_waiting_procs: HashMap<TimeoutId, (TracedProcessIdentifier, Syscall)>,
    address_to_name: HashMap<SocketAddress, String>,
    current_timeout: Option<data::Timeout>,
    current_message: Option<data::Message>,
    current_state: Option<serde_json::Value>,
    annotate_state_procs: HashMap<TracedProcessIdentifier, TracedProcessIdentifier>
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum SocketAddress {
    // for now, we only care about the port.
    IPV4(u16), IPV6(u16)
}

#[derive(Debug, Clone)]
enum Syscall {
    Brk,
    MProtect,
    ArchPrctl,
    Access(String),
    Open(String),
    Stat,
    Fstat(i32, File),
    MMap(i32, Option<File>),
    MUnmap,
    Close(i32, File),
    Read(i32, File),
    UDPSocket,
    Bind(i32, SocketAddress),
    Write(i32, File),
    RecvFrom(i32, File),
    SigProcMask,
    SigAction,
    NanoSleep,
    SendTo(i32, File, SocketAddress, Vec<u8>),
    SetTidAddress,
    SetRobustList,
    Futex,
    GetRLimit,
    Clone(CloneFlags),
    SigAltStack,
    SchedSetAffinity,
    SchedGetAffinity,
    Upcall(usize)
}

#[derive(Debug, Clone, Copy)]
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
                Self {tgid: child, tid: child, files: files}
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
    
    fn kill(&self, nthreads: usize) -> Result<(), Error> {
        // should only kill group leaders
        assert!(self.tid == self.tgid);
        trace!("Killing process {:?}", self);
        kill(self.tid, Signal::SIGKILL)?;
        for _i in 0..nthreads {
            let status = self.wait_status()?;
            match status {
                WaitStatus::Signaled(_, _, _) => (),
                _ => bail!("Unexpected wait status after killing process: {:?}",
                           status)
            }
        }
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
        loop {
            let status = waitpid(Pid::from_raw(-1), Some(WaitPidFlag::__WALL))?;
            if let WaitStatus::Stopped(pid, nix::sys::signal::Signal::SIGWINCH) = status {
                trace!("Got SIGWINCH, ignoring it and continuing");
                // this is a hack!
                ptrace::syscall(pid)?;
            } else {
                return Ok(status);
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
        let proc = Self {tgid: self.tgid, tid: child, files: (&self.files).clone()};
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
                buf = ptrace::read(self.tid, (addr + (i as u64)) as ptrace::AddressType)?.to_ne_bytes();
            }
            bytes.push(buf[i % size_of::<libc::c_long>()]);
            // addr incremented once for each *byte* read
        }
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
                Ok(SocketAddress::IPV4(sa.sin_port.to_be()))
            } else {
                bail!("Unsupported address family")
            }
        }
    }

    fn write_data(&self, addr: u64, addrlen: usize, data: Vec<u8>) -> Result<usize, Error> {
        let mut buf : [u8; size_of::<libc::c_long>()] = [0; size_of::<libc::c_long>()];
        let length = std::cmp::max(addrlen, data.len());
        for (i, b) in data.iter().enumerate() {
            buf[i % size_of::<libc::c_long>()] = *b;
            if ((i + 1) % size_of::<libc::c_long>() == 0) ||
                i + 1 == length {
                let word = libc::c_long::from_ne_bytes(buf);
                ptrace::write(self.tid, (addr + (i as u64)) as ptrace::AddressType,
                              word as *mut libc::c_void)?;
            }
            // exit early if we're not iterating over whole vector
            if i + 1 == length {
                break;
            }
        }
        Ok(length)
    }

    //TODO implement this
    fn write_socket_address(&self, _addr_ptr: u64, _addrlen: usize,
                            _addr: Option<SocketAddress>)
                            -> Result<(), Error> {
        Ok(())
    }
    
    fn get_syscall(&self) -> Result<Syscall, Error> {
        self.wait_on_syscall()?;
        let regs = self.get_registers()?;
        let call_number = regs.orig_rax;
        let call = match call_number {
            0 => { //read()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.get(&fd) {
                    Ok(Syscall::Read(fd, file.clone()))
                } else {
                    bail!("read() called on unknown file")
                }
            },
            1 => { //write()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.get(&fd) {
                    Ok(Syscall::Write(fd, file.clone()))
                } else {
                    bail!("write() called on unknown file")
                }
            }
            2 => { //open()
                let s = self.read_string(regs.rdi)?;
                Ok(Syscall::Open(s))
            }
            3 => { //close()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.get(&fd) {
                    Ok(Syscall::Close(fd, file.clone()))
                } else {
                    bail!("close() called on unknown file")
                }
            }
            4 => Ok(Syscall::Stat),
            5 => { //fstat()
                let fd = regs.rdi as i32;
                if let Some(file) = self.files.get(&fd) {
                    Ok(Syscall::Fstat(fd, file.clone()))
                } else {
                    bail!("fstat() called on unknown file")
                }
            }
            9 => { // mmap(), only supported for global files for now
                let fd = regs.r8 as i32;
                if fd < 0 {
                    Ok(Syscall::MMap(fd, None))
                } else {
                    if let Some(file) = self.files.get(&fd) {
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
            21 => { // access()
                let s = self.read_string(regs.rdi)?;
                Ok(Syscall::Access(s))
            },
            35 => Ok(Syscall::NanoSleep),
            41 => { // socket()
                let socket_family = regs.rdi as i32;
                let socket_type = regs.rsi as i32;
                let socket_protocol = regs.rdx as i32;
                // ensure this is a supported socket type
                if (socket_family == AddressFamily::Inet as i32 ||
                    socket_family == AddressFamily::Inet6 as i32) &&
                    socket_type == SockType::Datagram as i32 &&
                    socket_protocol == SockProtocol::Udp as i32 {
                    Ok(Syscall::UDPSocket)
                }
                else {
                    bail!("Unsupported socket({}, {}, {})",
                           socket_family, socket_type, socket_protocol);
                }
            },
            44 => { // sendto()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.get(&fd) {
                    let socket_address = self.read_socket_address(regs.r8, regs.r9 as usize)?;
                    let data = self.read_data(regs.rsi, regs.rdx as usize)?;
                    Ok(Syscall::SendTo(fd, sock.clone(), socket_address, data))
                } else {
                    bail!("sendto() called on unknown file")
                }
            }
            45 => { // recvfrom()
                let fd = regs.rdi as i32;
                if let Some(sock) = self.files.get(&fd) {
                    Ok(Syscall::RecvFrom(fd, sock.clone()))
                } else {
                    bail!("recvfrom() called on unknown file")
                }
            }
            49 => { // bind()
                let fd = regs.rdi as i32;
                let socket_address = self.read_socket_address(regs.rsi, regs.rdx as usize)?;
                Ok(Syscall::Bind(fd, socket_address))
            },
            56 => { // clone()
                let flags = CloneFlags::from_bits(regs.rdi as i32)
                    .ok_or(format_err!("Invalid clone() flags"))?;
                Ok(Syscall::Clone(flags))
            }
            97 => Ok(Syscall::GetRLimit),
            131 => Ok(Syscall::SigAltStack),
            158 => Ok(Syscall::ArchPrctl),
            // TODO: figure out if I need to actually worry about futexes
            202 => Ok(Syscall::Futex),
            203 => Ok(Syscall::SchedSetAffinity),
            204 => Ok(Syscall::SchedGetAffinity),
            218 => Ok(Syscall::SetTidAddress),
            273 => Ok(Syscall::SetRobustList),
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
            (Syscall::Open(filename), SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                // TODO: identify local files
                let file = File::GlobalFile(filename);
                trace!("Adding file {} -> {:?} to proc {:?}", fd, file, self);
                self.files.insert(fd, file);
            }
            (Syscall::Close(fd, _), SyscallReturn::Success(_)) => {
                trace!("Removing file {} from proc {:?}", fd, self);
                self.files.remove(&fd);
            }
            (Syscall::UDPSocket, SyscallReturn::Success(fd)) => {
                let fd = fd as i32;
                let file = File::UDPSocket(None);
                self.files.insert(fd, file);
            }
            (Syscall::Bind(fd, addr), SyscallReturn::Success(_)) => {
                if let Some(sock) = self.files.get_mut(&fd) {
                    trace!("Binding {:?} to {:?}", sock, addr);
                    let new_sock = match sock {
                        File::UDPSocket(_) => File::UDPSocket(Some(addr)),
                        _ => bail!("bind() on bad file {:?}", sock)
                    };
                    self.files.insert(fd, new_sock);
                } else {
                    bail!("bind() called on unknown file")
                }
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
        let written = self.write_data(buffer_ptr, buffer_len, data)?;
        if addr_ptr != 0 {
            self.write_socket_address(addr_ptr, addr_len, addr)?;
        }
        // return data len
        let mut regs = self.get_registers()?;
        regs.rax = written as u64;
        self.set_registers(regs)?;
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
              current_timeout: None,
              current_message: None,
              current_state: None}
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

    fn get_current_message(&mut self, from: String, to: String, data: Vec<u8>) -> data::Message {
        let mut message = self.current_message.take().unwrap_or_else(|| data::Message::new());
        message.from = from;
        message.to = to;
        message.raw.extend(data);
        message
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
        while let Some(procid) = stack.pop() {
            trace!("Filling response from process {:?}", procid);
            let proc = self.procs.get_mut(&procid).expect(
                &format!("Bad process identifier {:?}", procid));
            proc.run_until_syscall()?;
            let call = proc.get_syscall()?;
            trace!("Process {:?} called Syscall {:?}", proc, call);
            // check for unsupported calls and panic if necessary
            match &call {
                Syscall::Read(_, file) => {
                    match file {
                        File::GlobalFile(_) | File::Special => (),
                        _ => bail!("Unsupported read of file {:?}", file)
                    }
                }
                Syscall::Write(_, file) => {
                    match file {
                        File::Special => (),
                        _ => bail!("Unsupported write to file {:?}", file)
                    }
                }
                Syscall::MMap(_, Some(file)) => {
                    match file {
                        File::GlobalFile(_) => (),
                        _ => bail!("Unsupported mmap on file {:?}", file)
                    }
                },
                Syscall::RecvFrom(_, file) => {
                    match file {
                        File::UDPSocket(Some(_)) => (),
                        _ => bail!("Unsupported recvfrom on file {:?}", file)
                    }
                }
                Syscall::SendTo(_, file, _, _) => {
                    match file {
                        File::UDPSocket(_) => (),
                        _ => bail!("Unsupported sendto on file {:?}", file)
                    }
                }
                _ => ()
            }
            match &call {
                Syscall::RecvFrom(_, File::UDPSocket(Some(addr))) => {
                    proc.stop_syscall()?;
                    self.message_waiting_procs.insert(addr.clone(),
                                                      (procid.clone(), call.clone()));
                    // we're blocking, so we're done here
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
                Syscall::SendTo(_, File::UDPSocket(from_addr), to_addr, data) => {
                    proc.stop_syscall()?;
                    if let Some(to) = self.address_to_name.get(&to_addr) {
                        proc.wake_from_stopped_call(call.clone())?;
                        let raw = WireMessage {from: from_addr.clone(), to: to_addr.clone(), data: data.clone()};
                        let message = self.get_current_message(procid.name.clone(),
                                                               to.clone(),
                                                               serialize(&raw).unwrap());
                        response.messages.push(message);
                        // don't execute ordinary syscall return handling
                        // keep filling response
                        stack.push(procid.clone());
                    } else {
                        bail!("Send to unknown address {:?}", to_addr);
                    }
                }
                Syscall::Clone(_) => { // TODO: handle different clone flags differently?
                    let (tid, child) = proc.get_cloned_child()?;
                    // let parent finish syscall before starting to execute child
                    proc.run_until_syscall()?;
                    let ret = proc.get_syscall_return(call)?;
                    trace!("Process {:?} got syscall return {:?}", proc, ret);
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
                    trace!("Process {:?} got syscall return {:?}", proc, ret);
                    stack.push(procid.clone());
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
                            trace!("Process {:?} setting timeout type to {}",
                                   proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
                            self.new_timeout(ty);
                            stack.push(procid.clone());
                        }
                        2 => { // annotate message
                            let regs = proc.get_registers()?;
                            let ty = proc.read_string(regs.rdi)?;
                            trace!("Process {:?} setting message type to {}",
                                   proc, ty);
                            proc.stop_syscall()?;
                            proc.wake_from_stopped_call(call.clone())?;
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
                            trace!("Process {:?} setting current.{} to {}",
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
                            trace!("Process {:?} setting current.{} to {}",
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
                    trace!("Process {:?} got syscall return {:?}", proc, ret);
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
        self.get_state(procid.clone().parent_process(), response)?;
        Ok(())
    }

    pub fn handle_message(&mut self, message: data::Message, response: &mut data::Response)
                          -> Result<(), Error> {
        let node = message.to;
        let raw = message.raw;
        let wire_message : WireMessage = deserialize(&raw)?;
        if let Some((procid, _call)) = self.message_waiting_procs.get(&wire_message.to) {
            if procid.name != node {
                bail!("Message send to mismatched node ({} vs {})", procid.name, node);
            }
            // for now assume call is a recvfrom()
            let proc = self.procs.get_mut(procid).expect("Bad procid");
            proc.recvfrom_return(wire_message.from, wire_message.data)?;
            let procid = procid.clone();
            self.fill_response(procid.clone(), response)?;
            self.get_state(procid.parent_process(), response)?;
            Ok(())
        } else {
            bail!("Message to unknown recipient");
        }
    }

    pub fn handle_timeout(&mut self, timeout: data::Timeout,
                          response: &mut data::Response)
                          -> Result<(), Error> {
        let node = timeout.to;
        let raw = timeout.raw;
        let timeout_id = TimeoutId::from_bytes(&raw);
        if let Some((procid, call)) = self.timeout_waiting_procs.get(&timeout_id) {
            if procid.name != node {
                bail!("Timeout sent to mismatched node ({}, {})", procid.name, node);
            }
            let proc = self.procs.get_mut(procid).expect("Bad procid");
            proc.wake_from_stopped_call(call.clone())?;
            // always clear timeout
            // don't need raw field on cleared timeout
            response.cleared_timeouts.push(data::Timeout {
                to: node,
                ty: timeout.ty,
                body: timeout.body,
                raw: Vec::new()
            });
            let procid = procid.clone();
            self.fill_response(procid.clone(), response)?;
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
