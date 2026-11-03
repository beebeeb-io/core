//! Review-only allocator witness for the resumed-download offset.
//!
//! The chunk count in a response header is untrusted. `chunk_offset` must
//! answer from arithmetic alone: before the fix it materialised every boundary
//! (`Vec::with_capacity(chunk_count)`), so a huge declared count allocated
//! before the index was ever validated. No key or file bytes are involved.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use beebeeb_core::download::{MIN_FRAME_LEN, chunk_offset, compute_chunk_boundaries};

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

/// The pre-fix implementation: build every boundary, then index it.
fn old_chunk_offset(total_len: usize, chunk_count: u32, chunk_index: u32) -> Option<usize> {
    let boundaries = compute_chunk_boundaries(total_len, chunk_count).ok()?;
    boundaries.get(chunk_index as usize).map(|(start, _)| *start)
}

#[test]
fn arithmetic_offset_matches_the_old_boundary_rule() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for &(total, count) in &[(1000usize, 3u32), (56, 2), (100, 2), (1000, 7), (1_000_000, 31)] {
        for index in 0..count {
            assert_eq!(
                chunk_offset(total, count, index).unwrap(),
                old_chunk_offset(total, count, index).unwrap(),
                "total={total} count={count} index={index}"
            );
        }
    }
}

#[test]
fn a_huge_declared_count_is_answered_without_allocating() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // A variety of hostile counts, including one that would have built a
    // multi-gigabyte Vec of boundaries.
    let cases: &[(usize, u32)] = &[
        (MIN_FRAME_LEN * 100_000, 100_000),
        (MIN_FRAME_LEN * u32::MAX as usize, u32::MAX),
    ];
    for &(total, count) in cases {
        let index = count - 1;
        ALLOCATIONS.with(|n| n.set(0));
        CAPTURE.with(|c| c.set(true));
        let offset = chunk_offset(total, count, index).unwrap();
        CAPTURE.with(|c| c.set(false));
        assert_eq!(offset, MIN_FRAME_LEN * index as usize, "count={count}");
        assert_eq!(
            ALLOCATIONS.with(|n| n.get()),
            0,
            "chunk_offset allocated while computing a resume offset for count={count}"
        );
    }
}
