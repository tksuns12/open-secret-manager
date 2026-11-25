use std::sync::{Arc, Mutex, PoisonError};

use arboard::SetExtWindows;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Away;

type OnAway = Arc<dyn Fn(Away) + Send + Sync>;

/// Watches Windows session lock, console/remote disconnect, and suspend events
/// via a hidden top-level window registered with `WTSRegisterSessionNotification`.
pub(crate) fn watch(on_away: OnAway) -> bool {
    use core::ffi::c_void;
    use std::sync::mpsc;

    use windows_sys::Win32::{
        Foundation::{HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            RemoteDesktop::{WTSRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION},
        },
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            GetWindowLongPtrW, PostQuitMessage, RegisterClassW, SetWindowLongPtrW,
            TranslateMessage, GWLP_USERDATA, MSG, PBT_APMSUSPEND, WM_NCDESTROY, WM_POWERBROADCAST,
            WM_WTSSESSION_CHANGE, WNDCLASSW, WS_OVERLAPPED, WTS_CONSOLE_DISCONNECT,
            WTS_REMOTE_DISCONNECT, WTS_SESSION_LOCK,
        },
    };

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        let user_data = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) };
        if user_data != 0 {
            match msg {
                WM_WTSSESSION_CHANGE => {
                    // SAFETY: `user_data` holds a live `Box<OnAway>` installed
                    // immediately after `CreateWindowExW` and freed on `WM_NCDESTROY`.
                    let callback = unsafe { &*(user_data as *const OnAway) };
                    match wparam as u32 {
                        WTS_SESSION_LOCK => callback(Away::ScreenLocked),
                        WTS_CONSOLE_DISCONNECT | WTS_REMOTE_DISCONNECT => {
                            callback(Away::SwitchedOut);
                        }
                        _ => {}
                    }
                    return 0;
                }
                WM_POWERBROADCAST => {
                    if wparam as u32 == PBT_APMSUSPEND {
                        // SAFETY: as above.
                        let callback = unsafe { &*(user_data as *const OnAway) };
                        callback(Away::Sleep);
                    }
                    return 1;
                }
                WM_NCDESTROY => {
                    unsafe {
                        SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                        drop(Box::from_raw(user_data as *mut OnAway));
                        PostQuitMessage(0);
                    }
                    return 0;
                }
                _ => {}
            }
        }
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    let (ready_tx, ready_rx) = mpsc::sync_channel::<bool>(1);
    let spawned = std::thread::Builder::new()
        .name("osm-session-win".into())
        .spawn(move || {
            let class_name: Vec<u16> = "OpenSecretManagerSessionWatcher\0".encode_utf16().collect();
            // SAFETY: NULL asks for the current process module handle.
            let instance = unsafe { GetModuleHandleW(std::ptr::null()) };
            let wc = WNDCLASSW {
                style: 0,
                lpfnWndProc: Some(wnd_proc),
                cbClsExtra: 0,
                cbWndExtra: 0,
                hInstance: instance,
                hIcon: std::ptr::null_mut(),
                hCursor: std::ptr::null_mut(),
                hbrBackground: std::ptr::null_mut(),
                lpszMenuName: std::ptr::null(),
                lpszClassName: class_name.as_ptr(),
            };
            // SAFETY: `wc` is fully initialized and `class_name` is NUL-terminated.
            let _ = unsafe { RegisterClassW(&wc) };
            // Top-level hidden `WS_OVERLAPPED` window (NOT `HWND_MESSAGE`) so
            // Windows delivers broadcast `WM_POWERBROADCAST` suspend messages.
            // SAFETY: valid class name, process instance, and null optional params.
            let hwnd = unsafe {
                CreateWindowExW(
                    0,
                    class_name.as_ptr(),
                    class_name.as_ptr(),
                    WS_OVERLAPPED,
                    0,
                    0,
                    0,
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    instance,
                    std::ptr::null::<c_void>(),
                )
            };
            if hwnd.is_null() {
                let _ = ready_tx.send(false);
                return;
            }
            let boxed = Box::into_raw(Box::new(on_away));
            // SAFETY: `hwnd` is a valid window owned by this thread; `boxed`
            // is reclaimed on `WM_NCDESTROY`.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, boxed as isize) };
            // SAFETY: `hwnd` is a valid top-level window for this session.
            if unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) } == 0 {
                unsafe { DestroyWindow(hwnd) };
                let _ = ready_tx.send(false);
                return;
            }
            let _ = ready_tx.send(true);
            let mut msg: MSG = unsafe { std::mem::zeroed() };
            // SAFETY: standard Win32 message loop for the thread's window.
            while unsafe { GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) } > 0 {
                unsafe {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
        });
    if spawned.is_err() {
        return false;
    }
    ready_rx.recv().unwrap_or(false)
}

struct Served {
    key: [u8; 32],
    copies: isize,
    last: Option<(isize, [u8; 32])>,
}

static SERVED: Mutex<Option<Served>> = Mutex::new(None);

fn keyed_digest(key: &[u8; 32], text: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"osm-clipboard-v1");
    hasher.update(key);
    hasher.update(text.as_bytes());
    hasher.finalize().into()
}

/// Puts `text` on the Windows clipboard, excluded from clipboard monitoring,
/// local clipboard history, and Windows Cloud Clipboard.
pub(crate) fn copy_secret(text: &str) -> Option<isize> {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    if served.is_none() {
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).ok()?;
        *served = Some(Served {
            key,
            copies: 0,
            last: None,
        });
    }
    let served = served.as_mut()?;
    let mut clipboard = arboard::Clipboard::new().ok()?;
    clipboard
        .set()
        .exclude_from_monitoring()
        .exclude_from_history()
        .exclude_from_cloud()
        .text(text.to_owned())
        .ok()?;
    served.copies += 1;
    let digest = keyed_digest(&served.key, text);
    served.last = Some((served.copies, digest));
    Some(served.copies)
}

/// Clears the Windows clipboard if it still holds the last secret put there by
/// [`copy_secret`], and, given `copy`, only if that secret was that copy.
pub(crate) fn clear(copy: Option<isize>) {
    let mut served = SERVED.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(served) = served.as_mut() else {
        return;
    };
    let Some((last, expected)) = served.last else {
        return;
    };
    if copy.is_some_and(|copy| copy != last) {
        return;
    }
    if let Ok(mut clipboard) = arboard::Clipboard::new() {
        match clipboard.get_text() {
            Ok(current) => {
                let current = Zeroizing::new(current);
                if keyed_digest(&served.key, &current) == expected {
                    let _ = clipboard.clear();
                }
            }
            Err(_) => {
                let _ = clipboard.clear();
            }
        }
    }
    served.last = None;
}
