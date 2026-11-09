//! Local control channel: how a GUI (or another tool) asks a running daemon
//! what it is doing, without touching the network stack itself.
//!
//! # Why a protocol module rather than just a socket
//!
//! The transport is the part that cannot be tested here (a Windows named pipe
//! needs Windows), and the protocol is the part that decides whether a malformed
//! client can wedge the daemon. So the two are separated: everything in this
//! module except [`bind`] is plain `Read` + `Write` and is tested on every
//! platform, and the platform-specific code is reduced to "produce a stream
//! object".
//!
//! # The wire format
//!
//! One frame is a 4-byte big-endian length followed by that many bytes of UTF-8
//! text. The length is capped at [`MAX_FRAME`] *before* allocating, so a hostile
//! (or buggy) client cannot ask for a gigabyte. Requests are single lines;
//! responses are single lines except for `LIMITS`, whose first line is the count
//! and whose following lines are one entry each.
//!
//! ```text
//! client: HELLO 1              server: OK netrocket 0.3.0 proto 1
//! client: STATUS               server: OK packets 1200 bytes 900000 ... flows 12
//! client: LIMITS               server: OK 2
//!                                      chrome.exe 1000000 65536 ecn process
//! client: QUIT                 server: BYE
//! ```
//!
//! # Why read-only
//!
//! Changing a limit while the daemon runs means the packet thread and the
//! control thread share the engine. The engine is deliberately single-owner: no
//! lock, no atomic, nothing on the packet path. Rather than put a mutex on the
//! hot path to satisfy a GUI, this channel publishes a `Copy` snapshot once a
//! second and refuses mutations with a clear error until hot reload lands. A
//! control channel that can only lie about changing things would be worse than
//! none.
//!
//! Only the Windows daemon calls [`bind`] at run time. The tests drive it on
//! every platform, so on a Unix build rustc would otherwise report it as dead
//! code — the same reason `caps.rs` carries the attribute below.

#![cfg_attr(not(windows), allow(dead_code))]

use nr_core::config::Config;
use nr_core::stats::Snapshot;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Protocol version. Bumped whenever a request or response changes meaning.
pub const PROTO_VERSION: u32 = 1;

/// Largest frame either side will accept, in bytes.
///
/// 16 KiB is far more than a `LIMITS` listing needs for a realistic
/// configuration and small enough that a stuck client cannot disturb the
/// daemon's memory budget.
pub const MAX_FRAME: usize = 16 * 1024;

/// What the daemon publishes to the control channel.
///
/// The snapshot is `Copy` and replaced under a mutex once per second: the
/// packet thread never blocks on a client, and a slow client reads a stale
/// second at worst.
#[derive(Debug)]
pub struct Shared {
    /// Configuration as loaded at start-up (limits listed by `LIMITS`).
    pub config: Config,
    /// Latest published counters.
    pub snapshot: Mutex<Snapshot>,
}

impl Shared {
    /// Wrap a configuration and its first snapshot.
    #[must_use]
    pub fn new(config: Config, snapshot: Snapshot) -> Self {
        Self {
            config,
            snapshot: Mutex::new(snapshot),
        }
    }

    /// Replace the published snapshot (called from the daemon's tick).
    pub fn publish(&self, snapshot: Snapshot) {
        if let Ok(mut slot) = self.snapshot.lock() {
            *slot = snapshot;
        }
    }
}

/// One parsed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `HELLO <proto-version>`
    Hello(u32),
    /// `STATUS`
    Status,
    /// `LIMITS`
    Limits,
    /// `QUIT`
    Quit,
    /// Anything else, kept verbatim for the error message.
    Unknown(String),
}

impl Request {
    /// Parse one request line.
    #[must_use]
    pub fn parse(line: &str) -> Self {
        let mut parts = line.split_whitespace();
        match parts.next().map(str::to_ascii_uppercase).as_deref() {
            Some("HELLO") => match parts.next().and_then(|v| v.parse().ok()) {
                Some(v) => Self::Hello(v),
                None => Self::Unknown(line.trim().to_owned()),
            },
            Some("STATUS") => Self::Status,
            Some("LIMITS") => Self::Limits,
            Some("QUIT") | Some("EXIT") | Some("BYE") => Self::Quit,
            _ => Self::Unknown(line.trim().to_owned()),
        }
    }
}

/// What to do after answering a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum After {
    /// Keep the connection open.
    Keep,
    /// Answer, then close.
    Close,
}

/// Render the response to one request.
///
/// Public so a GUI test can pin the exact text a version of the daemon sends;
/// a protocol that only its own client has ever parsed is a protocol with bugs.
#[must_use]
pub fn respond(request: &Request, shared: &Shared) -> (String, After) {
    match request {
        Request::Hello(version) => {
            if *version == PROTO_VERSION {
                let name = nr_core::VERSION;
                let text = format!("OK netrocket {name} proto {PROTO_VERSION}");
                (text, After::Keep)
            } else {
                let text = format!("ERR version {version} unsupported, want {PROTO_VERSION}");
                (text, After::Close)
            }
        }
        Request::Status => {
            let snap = shared.snapshot.lock().map(|s| *s).unwrap_or_default();
            let text = format!(
                "OK packets {} bytes {} dropped {} flows {} retained {} marked {}",
                snap.packets,
                snap.bytes,
                snap.dropped_total(),
                snap.flows,
                snap.retained_bytes,
                snap.marked_ecn,
            );
            (text, After::Keep)
        }
        Request::Limits => {
            let mut text = format!("OK {}", shared.config.limits.len());
            for l in &shared.config.limits {
                text.push('\n');
                text.push_str(&format!(
                    "{} {} {} {} {}",
                    l.name,
                    l.rate_bps,
                    l.burst_bytes,
                    l.policy.as_str(),
                    l.scope.as_str()
                ));
            }
            (text, After::Keep)
        }
        Request::Quit => ("BYE".to_owned(), After::Close),
        Request::Unknown(line) => {
            // Echoing what was sent is a debugging aid; a client can be sure
            // the daemon understood *something*. Bounded by the frame limit.
            let text = format!("ERR unknown {}", sanitise(line));
            (text, After::Keep)
        }
    }
}

/// Make a client-supplied string safe to echo on one line.
fn sanitise(text: &str) -> String {
    let mut out = String::with_capacity(text.len().min(64));
    for c in text.chars().take(64) {
        out.push(if c.is_ascii_graphic() || c == ' ' {
            c
        } else {
            '?'
        });
    }
    if out.is_empty() {
        out.push_str("(empty)");
    }
    out
}

/// Read one frame, or `Ok(None)` on a clean end of stream.
///
/// A frame longer than [`MAX_FRAME`] is an error: the connection is dropped
/// rather than a large allocation made on a client's word.
pub fn read_frame<R: Read>(reader: &mut R) -> io::Result<Option<String>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty frame"));
    }
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME}-byte limit"),
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    String::from_utf8(body)
        .map(Some)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "frame is not UTF-8"))
}

/// Write one frame and flush it.
pub fn write_frame<W: Write>(writer: &mut W, body: &str) -> io::Result<()> {
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds the frame limit",
        ));
    }
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body.as_bytes())?;
    writer.flush()
}

/// Serve one connection until the client quits, closes, or misbehaves.
///
/// Returns the number of requests answered, so a caller can log something
/// truthful about the session.
pub fn serve<S: Read + Write>(stream: &mut S, shared: &Shared) -> io::Result<u64> {
    let mut served = 0u64;
    loop {
        let frame = match read_frame(&mut *stream)? {
            Some(f) => f,
            None => return Ok(served),
        };
        let request = Request::parse(&frame);
        let (text, after) = respond(&request, shared);
        write_frame(&mut *stream, &text)?;
        served += 1;
        if after == After::Close {
            return Ok(served);
        }
    }
}

/// Read and write on one connection — what a transport has to provide.
///
/// `Send` is part of the contract because the daemon hands the listener to its
/// control thread and every connection is moved into the loop there.
pub trait Stream: Read + Write + Send {}

impl<T: Read + Write + Send> Stream for T {}

// `Box<dyn Stream>` needs no forwarding impls of its own: `std` already
// implements `Read` and `Write` for `Box<R>` where `R: ?Sized`, and both traits
// are supertraits of `Stream`.

/// One accepted connection, whatever transport produced it.
pub type Connection = Box<dyn Stream>;

/// The listener both platforms hand back, so `serve_listener` has one shape.
pub type Listener = Box<dyn Iterator<Item = io::Result<Connection>> + Send>;

/// Serve clients forever on `listener`, one connection at a time.
///
/// One at a time is deliberate: a control channel is read by a UI that opens
/// one connection and polls it, and concurrent sessions would only add states
/// to reason about. The cost is honest: a client that connects and then goes
/// silent holds the channel until it disconnects. The UI keeps one connection
/// open and sends `STATUS` on a timer rather than reconnecting per poll.
pub fn serve_listener<L>(listener: L, shared: Arc<Shared>) -> io::Result<()>
where
    L: Iterator<Item = io::Result<Connection>>,
{
    for accepted in listener {
        let mut stream = accepted?;
        // Errors per connection are the client's problem, not the daemon's:
        // report and keep listening rather than take the channel down.
        if let Err(e) = serve(&mut stream, &shared) {
            eprintln!("control channel: client error: {e}");
        }
    }
    Ok(())
}

/// Create the platform's control endpoint, or explain why it could not.
///
/// * Windows: a named pipe with an explicit DACL that grants the current user
///   and nobody else, `PIPE_REJECT_REMOTE_CLIENTS`, and
///   `FILE_FLAG_FIRST_PIPE_INSTANCE` so the name cannot be squatted.
/// * Unix: a Unix domain socket with mode `0600`.
#[cfg(unix)]
pub fn bind(path: &Path) -> io::Result<Listener> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    // A stale socket from a crashed daemon would make `bind` fail with
    // EADDRINUSE; only unlink something that is actually a socket.
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        let _ = std::fs::remove_file(path);
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    // `incoming()` borrows the listener, so the iterator owns it instead.
    let sockets = listener;
    let connections = std::iter::from_fn(move || {
        Some(
            sockets
                .accept()
                .map(|(stream, _)| Box::new(stream) as Connection),
        )
    });
    Ok(Box::new(connections))
}

#[cfg(not(unix))]
/// Windows: see `win_pipe`.
pub fn bind(path: &Path) -> io::Result<Listener> {
    win_pipe::bind(path)
}

#[cfg(windows)]
mod win_pipe {
    //! The named-pipe half: create an instance with an explicit DACL, accept one
    //! client at a time, and expose the handle as `Read + Write` so the tested
    //! protocol loop above serves it unchanged.
    //!
    //! This is the only part of the control channel that cannot be exercised on
    //! any machine this project is built on; `docs/IPC.md` and `LIMITATIONS.md`
    //! say so explicitly.

    use std::ffi::{c_void, OsStr};
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    type Handle = *mut c_void;
    type Bool = i32;
    type Dword = u32;

    const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
    const PIPE_ACCESS_DUPLEX: Dword = 0x0000_0003;
    const FILE_FLAG_FIRST_PIPE_INSTANCE: Dword = 0x0008_0000;
    const PIPE_TYPE_BYTE: Dword = 0x0000_0000;
    const PIPE_READMODE_BYTE: Dword = 0x0000_0000;
    const PIPE_WAIT: Dword = 0x0000_0000;
    const PIPE_REJECT_REMOTE_CLIENTS: Dword = 0x0000_0008;
    const FILE_ALL_ACCESS: Dword = 0x001F_01FF;
    // The owner of the process, which is the user we are willing to serve.
    const TOKEN_USER_CLASS: u32 = 1;
    const SECURITY_DESCRIPTOR_REVISION: Dword = 1;
    const ACL_REVISION: Dword = 2;
    // Plenty for one SID of up to 68 bytes.
    const ACL_BUF_BYTES: usize = 256;

    #[repr(C)]
    struct SecurityAttributes {
        n_length: Dword,
        lp_security_descriptor: *mut c_void,
        b_inherit_handle: Bool,
    }

    #[repr(C, align(8))]
    struct SecurityDescriptor {
        revision: u8,
        size: u8,
        control: u16,
        owner: *mut c_void,
        group: *mut c_void,
        sacl: *mut c_void,
        dacl: *mut c_void,
    }

    /// `InitializeAcl` and `AddAccessAllowedAce` write through a pointer that
    /// has to be 4-byte aligned, which a `[u8; N]` is not.
    #[repr(C, align(4))]
    struct AclBuffer {
        bytes: [u8; ACL_BUF_BYTES],
    }

    #[repr(C)]
    struct SidAndAttributes {
        sid: *mut c_void,
        attributes: Dword,
    }

    #[repr(C)]
    struct TokenUser {
        user: SidAndAttributes,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn CreateNamedPipeW(
            name: *const u16,
            open_mode: Dword,
            pipe_mode: Dword,
            max_instances: Dword,
            out_buffer: Dword,
            in_buffer: Dword,
            timeout: Dword,
            attributes: *mut SecurityAttributes,
        ) -> Handle;
        fn ConnectNamedPipe(pipe: Handle, overlapped: *mut c_void) -> Bool;
        fn DisconnectNamedPipe(pipe: Handle) -> Bool;
        fn ReadFile(
            file: Handle,
            buffer: *mut u8,
            to_read: Dword,
            read: *mut Dword,
            overlapped: *mut c_void,
        ) -> Bool;
        fn WriteFile(
            file: Handle,
            buffer: *const u8,
            to_write: Dword,
            written: *mut Dword,
            overlapped: *mut c_void,
        ) -> Bool;
        fn CloseHandle(object: Handle) -> Bool;
        fn GetCurrentProcess() -> Handle;
        fn OpenProcessToken(process: Handle, access: Dword, token: *mut Handle) -> Bool;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            info: *mut c_void,
            len: Dword,
            needed: *mut Dword,
        ) -> Bool;
        fn InitializeSecurityDescriptor(descriptor: *mut c_void, revision: Dword) -> Bool;
        fn SetSecurityDescriptorDacl(
            descriptor: *mut c_void,
            present: Bool,
            dacl: *mut c_void,
            defaulted: Bool,
        ) -> Bool;
        fn InitializeAcl(acl: *mut c_void, len: Dword, revision: Dword) -> Bool;
        fn AddAccessAllowedAce(
            acl: *mut c_void,
            revision: Dword,
            mask: Dword,
            sid: *mut c_void,
        ) -> Bool;
    }

    const TOKEN_QUERY: Dword = 0x0008;

    fn last_error() -> io::Error {
        io::Error::last_os_error()
    }

    /// Build a security descriptor that allows exactly one user.
    struct AllowUser {
        descriptor: Box<SecurityDescriptor>,
        acl: Box<AclBuffer>,
        sid: *mut c_void,
        token_bytes: *mut u8,
        token_layout: std::alloc::Layout,
    }

    impl AllowUser {
        fn new() -> io::Result<Self> {
            unsafe {
                let mut needed: Dword = 0;
                let mut token: Handle = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(last_error());
                }
                let _ = GetTokenInformation(
                    token,
                    TOKEN_USER_CLASS,
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                );
                let _ = CloseHandle(token);
                if needed == 0 {
                    return Err(last_error());
                }
                let token_layout = std::alloc::Layout::from_size_align(needed as usize, 8)
                    .map_err(|_| io::Error::other("token buffer"))?;
                let token_bytes = std::alloc::alloc_zeroed(token_layout);
                if token_bytes.is_null() {
                    return Err(io::Error::other("out of memory"));
                }
                let mut user = AllowUser {
                    descriptor: Box::new(SecurityDescriptor {
                        revision: SECURITY_DESCRIPTOR_REVISION as u8,
                        size: std::mem::size_of::<SecurityDescriptor>() as u8,
                        control: 0,
                        owner: std::ptr::null_mut(),
                        group: std::ptr::null_mut(),
                        sacl: std::ptr::null_mut(),
                        dacl: std::ptr::null_mut(),
                    }),
                    acl: Box::new(AclBuffer {
                        bytes: [0u8; ACL_BUF_BYTES],
                    }),
                    sid: std::ptr::null_mut(),
                    token_bytes,
                    token_layout,
                };

                let mut token: Handle = std::ptr::null_mut();
                if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                    return Err(last_error());
                }
                let ok = GetTokenInformation(
                    token,
                    TOKEN_USER_CLASS,
                    token_bytes.cast::<c_void>(),
                    needed,
                    &mut needed,
                );
                let _ = CloseHandle(token);
                if ok == 0 {
                    return Err(last_error());
                }
                user.sid = (*token_bytes.cast::<TokenUser>()).user.sid;

                let acl_ptr = user.acl.bytes.as_mut_ptr().cast::<c_void>();
                if InitializeAcl(acl_ptr, ACL_BUF_BYTES as Dword, ACL_REVISION) == 0 {
                    return Err(last_error());
                }
                if AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, user.sid) == 0 {
                    return Err(last_error());
                }
                let sd_ptr = (&mut *user.descriptor as *mut SecurityDescriptor).cast::<c_void>();
                if InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0 {
                    return Err(last_error());
                }
                // present = TRUE, defaulted = FALSE: the DACL above is the whole
                // story, and an empty one would deny everyone.
                if SetSecurityDescriptorDacl(sd_ptr, 1, acl_ptr, 0) == 0 {
                    return Err(last_error());
                }
                Ok(user)
            }
        }

        fn attributes(&mut self) -> SecurityAttributes {
            SecurityAttributes {
                n_length: std::mem::size_of::<SecurityAttributes>() as Dword,
                lp_security_descriptor: (&mut *self.descriptor as *mut SecurityDescriptor)
                    .cast::<c_void>(),
                b_inherit_handle: 0,
            }
        }
    }

    impl Drop for AllowUser {
        fn drop(&mut self) {
            unsafe {
                std::alloc::dealloc(self.token_bytes, self.token_layout);
            }
        }
    }

    /// One accepted pipe instance, usable as a byte stream.
    ///
    /// The handle is kept as a `usize` so this type is plainly `Send`: a Win32
    /// handle is a process-wide number rather than a pointer into some other
    /// thread's memory, and this one is created, used and closed by a single
    /// thread at a time. Storing the raw pointer instead would need an
    /// `unsafe impl Send` around something that is not actually unsafe.
    struct Pipe {
        handle: usize,
    }

    impl Pipe {
        fn handle(&self) -> Handle {
            self.handle as Handle
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let mut read: Dword = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle(),
                    buf.as_mut_ptr(),
                    buf.len().min(Dword::MAX as usize) as Dword,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(read as usize)
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut written: Dword = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle(),
                    buf.as_ptr(),
                    buf.len().min(Dword::MAX as usize) as Dword,
                    &mut written,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(last_error());
            }
            Ok(written as usize)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            unsafe {
                let _ = DisconnectNamedPipe(self.handle());
                let _ = CloseHandle(self.handle());
            }
        }
    }

    /// `C:\...` or `netrocket` -> `\\.\pipe\netrocket`.
    fn pipe_name(path: &Path) -> io::Result<Vec<u16>> {
        let raw = path.to_string_lossy();
        let name = if raw.starts_with(r"\\.\pipe\") {
            raw.into_owned()
        } else {
            format!(r"\\.\pipe\{}", raw.trim_start_matches('/'))
        };
        let mut wide: Vec<u16> = OsStr::new(&name).encode_wide().collect();
        wide.push(0);
        Ok(wide)
    }

    pub fn bind(path: &Path) -> io::Result<super::Listener> {
        let name = pipe_name(path)?;
        Ok(Box::new(PipeFactory { name }))
    }

    /// Creates one instance per connection, as named pipes require.
    struct PipeFactory {
        name: Vec<u16>,
    }

    impl Iterator for PipeFactory {
        type Item = io::Result<super::Connection>;

        fn next(&mut self) -> Option<Self::Item> {
            let mut allow = match AllowUser::new() {
                Ok(a) => a,
                Err(e) => return Some(Err(e)),
            };
            let mut attributes = allow.attributes();
            let handle = unsafe {
                CreateNamedPipeW(
                    self.name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    MAX_BUFFER,
                    MAX_BUFFER,
                    0,
                    &mut attributes,
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                // `serve_listener` closes the previous instance before asking
                // for the next one, so a fresh create should succeed; if it
                // does not, the caller reports it and the daemon keeps shaping
                // without a control channel.
                return Some(Err(last_error()));
            }
            let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
            if connected == 0 {
                let err = last_error();
                // ERROR_PIPE_CONNECTED means a client arrived in between; that
                // is success.
                if err.raw_os_error() != Some(535) {
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                    return Some(Err(err));
                }
            }
            Some(Ok(Box::new(Pipe {
                handle: handle as usize,
            }) as super::Connection))
        }
    }

    /// Pipe buffers: enough for one maximum frame in each direction.
    const MAX_BUFFER: Dword = super::MAX_FRAME as Dword / 4;
}

#[cfg(test)]
mod tests {
    use super::*;
    use nr_core::Config;

    fn shared() -> Arc<Shared> {
        let text = "limit chrome.exe = 8mbit burst 64kb policy ecn\n";
        let (config, _) = Config::parse(text).unwrap();
        let snapshot = Snapshot {
            packets: 1200,
            bytes: 900_000,
            flows: 12,
            ..Snapshot::default()
        };
        Arc::new(Shared::new(config, snapshot))
    }

    /// A stream that connects a writer to a reader, for protocol tests.
    struct Duplex {
        reader: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Duplex {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn framed(lines: &[&str]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for line in lines {
            bytes.extend_from_slice(&(line.len() as u32).to_be_bytes());
            bytes.extend_from_slice(line.as_bytes());
        }
        bytes
    }

    fn decode_frames(bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = bytes;
        while rest.len() >= 4 {
            let len = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let body = &rest[4..4 + len];
            out.push(String::from_utf8(body.to_vec()).unwrap());
            rest = &rest[4 + len..];
        }
        out
    }

    #[test]
    fn hello_reports_the_version_and_refuses_others() {
        let shared = shared();
        let (text, after) = respond(&Request::Hello(PROTO_VERSION), &shared);
        assert!(text.starts_with("OK netrocket"), "{text}");
        assert!(text.ends_with(&format!("proto {PROTO_VERSION}")));
        assert_eq!(after, After::Keep);

        let (text, after) = respond(&Request::Hello(PROTO_VERSION + 1), &shared);
        assert!(text.starts_with("ERR version"), "{text}");
        assert_eq!(after, After::Close, "a mismatched client is not served");
    }

    #[test]
    fn status_reports_the_published_counters() {
        let shared = shared();
        let (text, _) = respond(&Request::Status, &shared);
        assert!(text.starts_with("OK "), "{text}");
        assert!(text.contains("packets 1200"), "{text}");
        assert!(text.contains("flows 12"), "{text}");
        assert!(text.contains("dropped 0"), "{text}");
    }

    #[test]
    fn limits_lists_every_configured_limit_with_its_policy() {
        let shared = shared();
        let (text, _) = respond(&Request::Limits, &shared);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "OK 1");
        assert_eq!(lines[1], "chrome.exe 1000000 64000 ecn process");
    }

    #[test]
    fn unknown_requests_are_answered_without_echoing_control_characters() {
        let shared = shared();
        let (text, after) = respond(&Request::parse("FROB\x07\x1b"), &shared);
        assert!(text.starts_with("ERR unknown "), "{text}");
        assert!(!text.contains('\x07'), "control characters must be escaped");
        assert_eq!(after, After::Keep);
    }

    #[test]
    fn an_oversized_frame_is_refused_before_allocating_it() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        let mut reader = std::io::Cursor::new(bytes);
        let err = read_frame(&mut reader).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn an_empty_frame_is_refused() {
        let mut reader = std::io::Cursor::new(0u32.to_be_bytes().to_vec());
        assert!(read_frame(&mut reader).is_err());
    }

    #[test]
    fn a_truncated_frame_is_an_error_not_a_hang() {
        let mut bytes = 10u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(b"HELLO");
        let mut reader = std::io::Cursor::new(bytes);
        assert!(read_frame(&mut reader).is_err());
    }

    #[test]
    fn clean_end_of_stream_is_not_an_error() {
        let mut reader = std::io::Cursor::new(Vec::new());
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn serve_answers_until_quit_and_then_stops() {
        let shared = shared();
        let mut stream = Duplex {
            reader: std::io::Cursor::new(framed(&["HELLO 1", "STATUS", "QUIT", "STATUS"])),
            written: Vec::new(),
        };
        let served = serve(&mut stream, &shared).unwrap();
        assert_eq!(served, 3, "the request after QUIT must not be answered");

        let frames = decode_frames(&stream.written);
        assert_eq!(frames.len(), 3);
        assert!(frames[0].starts_with("OK netrocket"));
        assert!(frames[1].contains("packets 1200"), "{}", frames[1]);
        assert_eq!(frames[2], "BYE");
    }

    /// A connection that keeps what the server wrote, so the test can read
    /// the responses after the server has dropped its end.
    struct Recording {
        reader: std::io::Cursor<Vec<u8>>,
        written: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for Recording {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reader.read(buf)
        }
    }

    impl Write for Recording {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.written.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_listener_loop_survives_a_client_that_disconnects_mid_frame() {
        let shared = shared();
        let good = Arc::new(Mutex::new(Vec::new()));
        let streams: Vec<io::Result<Connection>> = vec![
            // Dies in the middle of a frame: the loop must report it and go on.
            Ok(Box::new(Recording {
                reader: std::io::Cursor::new(vec![0, 0, 0, 8, b'H', b'E']),
                written: Arc::new(Mutex::new(Vec::new())),
            })),
            Ok(Box::new(Recording {
                reader: std::io::Cursor::new(framed(&["STATUS", "QUIT"])),
                written: Arc::clone(&good),
            })),
        ];
        serve_listener(streams.into_iter(), shared).unwrap();

        let frames = decode_frames(&good.lock().unwrap());
        assert_eq!(frames.len(), 2, "the second client was still served");
        assert!(frames[0].contains("packets 1200"), "{}", frames[0]);
        assert_eq!(frames[1], "BYE");
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_socket_round_trip_serves_a_real_client() {
        use std::io::BufReader;

        let dir = std::env::temp_dir().join(format!("nr-ipc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ctl.sock");

        let shared = shared();
        let listener = bind(&path).unwrap();
        // Mode 0600: only the owner may connect.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "the socket must be owner-only");
        }

        let server = std::thread::spawn(move || {
            // One client, then stop: the test drives the listener directly so
            // it does not have to signal a long-running loop.
            let mut conns = listener;
            if let Some(Ok(mut stream)) = conns.next() {
                serve(&mut stream, &shared).unwrap();
            }
        });

        let mut client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        write_frame(&mut client, "HELLO 1").unwrap();
        write_frame(&mut client, "STATUS").unwrap();
        write_frame(&mut client, "LIMITS").unwrap();
        write_frame(&mut client, "QUIT").unwrap();

        let mut reader = BufReader::new(client);
        let hello = read_frame(&mut reader).unwrap().unwrap();
        assert!(hello.starts_with("OK netrocket"), "{hello}");
        let status = read_frame(&mut reader).unwrap().unwrap();
        assert!(status.contains("packets 1200"), "{status}");
        let limits = read_frame(&mut reader).unwrap().unwrap();
        assert!(limits.starts_with("OK 1"), "{limits}");
        assert_eq!(read_frame(&mut reader).unwrap().unwrap(), "BYE");

        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
