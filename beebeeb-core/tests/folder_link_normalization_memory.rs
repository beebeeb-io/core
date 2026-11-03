//! Review-only allocator witness. The only searched bytes are a public fixture.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use zeroize::Zeroizing;

struct Witness;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const MARKER: &[u8] = b"rv44-public-";

// Capture state is PER THREAD. libtest runs each test on its own thread and
// other threads (the harness, other tests) allocate concurrently, so a
// process-global flag inspected their buffers as well. Const-initialised
// non-`Drop` cells: touching them cannot allocate, and `try_with` below reports
// teardown instead of panicking in the allocator.
thread_local! {
    static CAPTURE: Cell<bool> = const { Cell::new(false) };
    static UNWIPED_REALLOCS: Cell<usize> = const { Cell::new(0) };
}

/// Allocator-side capture read: never allocates, never panics. During thread
/// teardown `try_with` returns `Err`, which reads as "not capturing".
fn capturing() -> bool {
    CAPTURE.try_with(|c| c.get()).unwrap_or(false)
}

fn count_unwiped() {
    let _ = UNWIPED_REALLOCS.try_with(|n| n.set(n.get().wrapping_add(1)));
}

// Zero-init allocations in this diagnostic process, making reads of byte-buffer
// slack defined. No key/password bytes or allocation contents are printed.
unsafe fn inspect(p: *mut u8, layout: Layout) {
    if capturing() && layout.align() <= 4 && layout.size() >= 16 {
        let b = unsafe { std::slice::from_raw_parts(p, layout.size()) };
        if b.windows(MARKER.len()).any(|x| x == MARKER) || b.windows(4).any(|x| x == [0x5c, 3, 0, 0]) {
            count_unwiped();
        }
    }
}
unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe {
            inspect(p, layout);
            System.dealloc(p, layout)
        }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let new_layout = Layout::from_size_align(size, layout.align()).unwrap();
        let q = unsafe { System.alloc_zeroed(new_layout) };
        if q.is_null() {
            return q;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(p, q, layout.size().min(size));
        }
        if capturing() && layout.align() <= 4 && layout.size() >= MARKER.len() {
            let bytes = unsafe { std::slice::from_raw_parts(p, layout.size()) };
            if bytes.windows(MARKER.len()).any(|b| b == MARKER) || bytes.windows(4).any(|b| b == [0x5c, 3, 0, 0]) {
                count_unwiped();
            }
        }
        unsafe {
            System.dealloc(p, layout);
        }
        q
    }
}
#[global_allocator]
static ALLOCATOR: Witness = Witness;

#[test]
fn preallocated_zeroizing_string_control() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = "rv44-public-".repeat(128);
    let mut s = Zeroizing::new(String::with_capacity(fixture.len()));
    UNWIPED_REALLOCS.with(|n| n.set(0));
    CAPTURE.with(|c| c.set(true));
    s.push_str(&fixture);
    drop(s);
    CAPTURE.with(|c| c.set(false));
    assert_eq!(UNWIPED_REALLOCS.with(|n| n.get()), 0);
}

#[test]
fn nfc_collection_never_releases_unwiped_passphrase_fragments() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = "rv44-public-".repeat(128);
    UNWIPED_REALLOCS.with(|n| n.set(0));
    CAPTURE.with(|c| c.set(true));
    let result = beebeeb_core::kdf::derive_folder_link_passphrase_stretch(&fixture, "token");
    CAPTURE.with(|c| c.set(false));
    assert!(result.is_ok());
    assert_eq!(
        UNWIPED_REALLOCS.with(|n| n.get()),
        0,
        "NFC collection released old allocations containing public passphrase fragments without wiping"
    );
}

#[test]
fn normalizer_scratch_is_wiped() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = format!("rv44-public-{}{}", "\u{35c}".repeat(128), "\u{323}".repeat(128));
    UNWIPED_REALLOCS.with(|n| n.set(0));
    CAPTURE.with(|c| c.set(true));
    let result = beebeeb_core::kdf::derive_folder_link_passphrase_stretch(&fixture, "token");
    CAPTURE.with(|c| c.set(false));
    assert!(result.is_ok());
    assert_eq!(UNWIPED_REALLOCS.with(|n| n.get()), 0, "unwiped normalization scratch");
}
