//! Review-only allocator witness for the recovery-phrase word counter.
//!
//! Counting words is on the paste UI's hot path and its input is the master
//! secret. Before the fix the counter materialised a normalised copy of the
//! phrase; it must now count in place, with no allocation at all. No phrase or
//! key bytes are printed.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use beebeeb_core::recovery::phrase_word_count;

struct Witness;
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

// Capture state is PER THREAD. libtest runs each test on its own thread and
// other threads (the harness, other tests) allocate concurrently, so a
// process-global flag counted their allocations as well. Const-initialised
// non-`Drop` cells: touching them cannot allocate, and `try_with` below reports
// teardown instead of panicking in the allocator.
thread_local! {
    static CAPTURE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// Allocator-side capture read: never allocates, never panics. During thread
/// teardown `try_with` returns `Err`, which reads as "not capturing".
fn capturing() -> bool {
    CAPTURE.try_with(|c| c.get()).unwrap_or(false)
}

fn count_allocation() {
    let _ = ALLOCATIONS.try_with(|n| n.set(n.get().wrapping_add(1)));
}

unsafe impl GlobalAlloc for Witness {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if capturing() {
            count_allocation();
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if capturing() {
            count_allocation();
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        if capturing() {
            count_allocation();
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
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident";
    ALLOCATIONS.with(|n| n.set(0));
    CAPTURE.with(|c| c.set(true));
    let count = phrase_word_count(phrase);
    CAPTURE.with(|c| c.set(false));
    assert_eq!(count, 12);
    assert_eq!(
        ALLOCATIONS.with(|n| n.get()),
        0,
        "phrase_word_count allocated while counting a pasted phrase"
    );
}
