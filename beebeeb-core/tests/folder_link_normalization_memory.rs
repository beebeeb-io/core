//! Review-only allocator witness. The only searched bytes are a public fixture.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use zeroize::Zeroizing;

struct Witness;
static CAPTURE: AtomicBool = AtomicBool::new(false);
static UNWIPED_REALLOCS: AtomicUsize = AtomicUsize::new(0);
const MARKER: &[u8] = b"rv44-public-";

// Zero-init allocations in this diagnostic process, making reads of byte-buffer
// slack defined. No key/password bytes or allocation contents are printed.
unsafe fn inspect(p: *mut u8, layout: Layout) {
    if CAPTURE.load(Ordering::SeqCst) && layout.align() <= 4 && layout.size() >= 16 {
        let b = unsafe { std::slice::from_raw_parts(p, layout.size()) };
        if b.windows(MARKER.len()).any(|x| x == MARKER)
            || b.windows(16)
                .any(|x| x == [0x5c, 3, 0, 0, 0x5c, 3, 0, 0, 0x5c, 3, 0, 0, 0x5c, 3, 0, 0])
        {
            UNWIPED_REALLOCS.fetch_add(1, Ordering::SeqCst);
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
        if CAPTURE.load(Ordering::SeqCst) && layout.align() <= 4 && layout.size() >= MARKER.len() {
            let bytes = unsafe { std::slice::from_raw_parts(p, layout.size()) };
            if bytes.windows(MARKER.len()).any(|b| b == MARKER)
                || bytes
                    .windows(16)
                    .any(|b| b == [0x5c, 3, 0, 0, 0x5c, 3, 0, 0, 0x5c, 3, 0, 0, 0x5c, 3, 0, 0])
            {
                UNWIPED_REALLOCS.fetch_add(1, Ordering::SeqCst);
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
    let fixture = "rv44-public-".repeat(128);
    let mut s = Zeroizing::new(String::with_capacity(fixture.len()));
    UNWIPED_REALLOCS.store(0, Ordering::SeqCst);
    CAPTURE.store(true, Ordering::SeqCst);
    s.push_str(&fixture);
    drop(s);
    CAPTURE.store(false, Ordering::SeqCst);
    assert_eq!(UNWIPED_REALLOCS.load(Ordering::SeqCst), 0);
}

#[test]
fn nfc_collection_never_releases_unwiped_passphrase_fragments() {
    let fixture = "rv44-public-".repeat(128);
    UNWIPED_REALLOCS.store(0, Ordering::SeqCst);
    CAPTURE.store(true, Ordering::SeqCst);
    let result = beebeeb_core::kdf::derive_folder_link_passphrase_stretch(&fixture, "token");
    CAPTURE.store(false, Ordering::SeqCst);
    assert!(result.is_ok());
    assert_eq!(
        UNWIPED_REALLOCS.load(Ordering::SeqCst),
        0,
        "NFC collection released old allocations containing public passphrase fragments without wiping"
    );
}

#[test]
fn normalizer_scratch_is_wiped() {
    let fixture = format!("rv44-public-{}{}", "\u{35c}".repeat(128), "\u{323}".repeat(128));
    UNWIPED_REALLOCS.store(0, Ordering::SeqCst);
    CAPTURE.store(true, Ordering::SeqCst);
    let result = beebeeb_core::kdf::derive_folder_link_passphrase_stretch(&fixture, "token");
    CAPTURE.store(false, Ordering::SeqCst);
    assert!(result.is_ok());
    assert_eq!(
        UNWIPED_REALLOCS.load(Ordering::SeqCst),
        0,
        "unwiped normalization scratch"
    );
}
