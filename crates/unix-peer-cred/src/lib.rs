//! Isolated Unix domain socket peer UID inspection.
//!
//! Keeps the minimal `unsafe` OS call (`getpeereid` on macOS/BSD,
//! `SO_PEERCRED` on Linux/Android) out of `osm-browser-link`, which maintains
//! `#![forbid(unsafe_code)]`.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(unix)]
use std::{
    io,
    os::unix::{io::AsRawFd, net::UnixStream},
};

/// Returns the effective user ID of the peer connected on `stream`.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut euid: libc::uid_t = 0;
    let mut egid: libc::gid_t = 0;
    // SAFETY: `stream.as_raw_fd()` is an open Unix domain socket descriptor and
    // both out-pointers point to valid stack-allocated values for the call.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
    if rc == 0 {
        Ok(euid)
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Returns the effective user ID of the peer connected on `stream`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream.as_raw_fd()` is an open Unix domain socket descriptor,
    // `&mut cred` has size `len`, and `getsockopt` writes at most `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc == 0 && len == std::mem::size_of::<libc::ucred>() as libc::socklen_t {
        Ok(cred.uid)
    } else if rc == 0 {
        Err(io::Error::other("unexpected SO_PEERCRED length"))
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        target_os = "linux",
        target_os = "android"
    ))
))]
pub fn peer_uid(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credential lookup is unsupported on this Unix target",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn peer_uid_matches_own_euid_over_unix_pair() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let own = unsafe { libc::geteuid() };
        assert_eq!(peer_uid(&a).unwrap(), own);
    }
}
