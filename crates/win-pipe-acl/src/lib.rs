//! Isolated Windows Named Pipe owner-only SID DACL wrapper.
//!
//! All other crates in the workspace enforce `#![forbid(unsafe_code)]`. This
//! tiny crate holds the minimal Win32 FFI needed on Windows to attach a
//! protected owner-only DACL (`D:P(A;;GA;;;<USER_SID>)`) to every named pipe
//! instance created for the browser native-messaging IPC.

#![deny(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(windows), forbid(unsafe_code))]

#[cfg(windows)]
mod imp {
    use std::{ffi::c_void, io, mem::size_of, ptr};

    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, HANDLE, HLOCAL},
        Security::{
            Authorization::{
                ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
                SDDL_REVISION_1,
            },
            GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
            TOKEN_USER,
        },
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is an open Win32 handle owned exclusively by this guard.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    struct LocalFreeGuard(HLOCAL);

    impl Drop for LocalFreeGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` was allocated by `ConvertSidToStringSidW` or
                // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is freed once.
                unsafe { LocalFree(self.0) };
            }
        }
    }

    /// Returns the UTF-16 SDDL string `D:P(A;;GA;;;<CURRENT_USER_SID>)\0` so
    /// only the current process's user SID has access to the pipe.
    fn current_user_sddl() -> io::Result<Vec<u16>> {
        let mut raw_token: HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentProcess()` returns a pseudo-handle valid for the current process,
        // and `raw_token` is a valid out-pointer.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = HandleGuard(raw_token);

        let mut needed: u32 = 0;
        // SAFETY: Passing a null buffer with length 0 queries the required byte size.
        let probe =
            unsafe { GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
        if probe != 0 || needed == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(err);
            }
        }
        if needed == 0 {
            return Err(io::Error::other("empty TokenUser buffer size"));
        }

        // Align for `TOKEN_USER` (contains pointers) using `u64` words.
        let words = (needed as usize).div_ceil(size_of::<u64>());
        let mut buf = vec![0_u64; words];
        let mut actual: u32 = 0;
        // SAFETY: `buf` is properly aligned and at least `needed` bytes long.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut actual,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if (actual as usize) < size_of::<TOKEN_USER>() {
            return Err(io::Error::other("truncated TOKEN_USER response"));
        }

        // SAFETY: `GetTokenInformation(TokenUser)` initialized a `TOKEN_USER` at `buf`.
        let user_sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        if user_sid.is_null() {
            return Err(io::Error::other("null user SID in process token"));
        }

        let mut sid_wstr: *mut u16 = ptr::null_mut();
        // SAFETY: `user_sid` points inside `buf` for the duration of this call; `sid_wstr`
        // receives a NUL-terminated UTF-16 string allocated via LocalAlloc.
        if unsafe { ConvertSidToStringSidW(user_sid, &mut sid_wstr) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _sid_guard = LocalFreeGuard(sid_wstr.cast::<c_void>());
        if sid_wstr.is_null() {
            return Err(io::Error::other("null SID string pointer"));
        }

        let mut sid_len = 0usize;
        // SAFETY: `ConvertSidToStringSidW` guarantees a NUL-terminated UTF-16 string.
        while unsafe { *sid_wstr.add(sid_len) } != 0 {
            sid_len += 1;
            if sid_len > 256 {
                return Err(io::Error::other("unterminated SID string"));
            }
        }
        // SAFETY: `sid_wstr` is valid for `sid_len` u16 elements.
        let sid_slice = unsafe { std::slice::from_raw_parts(sid_wstr, sid_len) };

        let mut sddl: Vec<u16> = "D:P(A;;GA;;;".encode_utf16().collect();
        sddl.extend_from_slice(sid_slice);
        sddl.extend(")".encode_utf16());
        sddl.push(0);
        Ok(sddl)
    }

    /// Creates a Windows named pipe server instance restricted to the current
    /// user's SID via a protected owner-only DACL (`D:P(A;;GA;;;<USER_SID>)`)
    /// and rejecting remote network clients.
    pub fn create_owner_only_pipe(
        name: &str,
        first_pipe_instance: bool,
    ) -> io::Result<NamedPipeServer> {
        let sddl = current_user_sddl()?;
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `sddl` is a NUL-terminated UTF-16 string; `sd` receives a
        // LocalAlloc-owned security descriptor freed by `LocalFreeGuard`.
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if converted == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        let _sd_guard = LocalFreeGuard(sd);

        let mut attrs = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options
            .first_pipe_instance(first_pipe_instance)
            .reject_remote_clients(true);
        // SAFETY: `attrs` is a properly initialized `SECURITY_ATTRIBUTES` struct
        // whose `lpSecurityDescriptor` remains valid until `create_with_security_attributes_raw`
        // returns.
        unsafe {
            options.create_with_security_attributes_raw(
                name,
                (&mut attrs as *mut SECURITY_ATTRIBUTES).cast::<c_void>(),
            )
        }
    }
}

#[cfg(windows)]
pub use imp::create_owner_only_pipe;
