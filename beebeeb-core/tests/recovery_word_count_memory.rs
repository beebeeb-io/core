//! Review-only allocator witness for the recovery-phrase word counter.
//!
//! Counting words is on the paste UI's hot path and its input is the master
//! secret. Before the fix the counter materialised a normalised copy of the
//! phrase; it must now count in place, with no allocation at all. No phrase or
//! key bytes are printed.
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use beebeeb_core::recovery::phrase_word_count;

struct Witness;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
static CAPTURE: AtomicBool = AtomicBool::new(false);
static ALLOCATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if CAPTURE.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if CAPTURE.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if CAPTURE.load(Ordering::SeqCst) {
            ALLOCATIONS.fetch_add(1, Ordering::SeqCst);
        }
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Witness = Witness;

#[test]
fn counting_words_does_not_allocate() {
    let _serial = SERIAL.lock().unwrap();
    let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    ALLOCATIONS.store(0, Ordering::SeqCst);
    CAPTURE.store(true, Ordering::SeqCst);
    let count = phrase_word_count(phrase);
    CAPTURE.store(false, Ordering::SeqCst);
    assert_eq!(count, 12);
    assert_eq!(
        ALLOCATIONS.load(Ordering::SeqCst),
        0,
        "phrase_word_count allocated while counting a pasted phrase"
    );
}
