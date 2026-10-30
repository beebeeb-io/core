//! A zeroing global allocator for the wasm32 target (task 2254, decision L17).
//!
//! Every `&[u8]` argument wasm-bindgen hands to an export is a temporary copy in
//! linear memory: the JS glue allocates it with `__wbindgen_malloc` /
//! `__wbindgen_realloc` and frees it with `__wbindgen_free`
//! (`wasm-bindgen-0.2.118/src/rt/mod.rs` lines 16, 507, 521, 561-568), which are
//! thin wrappers over `alloc::alloc::{alloc, realloc, dealloc}` — i.e. over the
//! registered `#[global_allocator]`. The same wrappers free the `Vec<u8>` /
//! `String` buffers an export returns before the JS copy is handed back.
//!
//! Wrapping `System` and zeroing each block as it is released therefore wipes
//! those temporary copies of passwords, key material and plaintext inside the
//! WASM heap before dlmalloc can reuse the memory. Nothing else changes: the
//! pointer, size and alignment behaviour of every allocation is exactly the
//! system allocator's.
//!
//! Scope: heap blocks only. Rust's shadow stack and static data live below
//! `__heap_base`, so they are not touched by this allocator (see the L17
//! contract's residual-risk list).

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{Ordering, compiler_fence};
use std::alloc::System;

/// Wraps the system allocator; wipes a block before handing it back.
pub struct ZeroingAllocator;

unsafe impl GlobalAlloc for ZeroingAllocator {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    /// Wipe the whole block, then free it.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe {
            wipe(ptr, layout.size());
            System.dealloc(ptr, layout)
        }
    }

    /// Allocate the new block, copy `min(old, new)` bytes, wipe the old block,
    /// free it. On allocation failure nothing is wiped: the caller keeps its
    /// block, exactly as `GlobalAlloc`'s `realloc` contract requires.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        unsafe {
            let new_layout = Layout::from_size_align_unchecked(new_size, layout.align());
            let new_ptr = System.alloc(new_layout);
            if !new_ptr.is_null() {
                let copy = core::cmp::min(layout.size(), new_size);
                core::ptr::copy_nonoverlapping(ptr, new_ptr, copy);
                wipe(ptr, layout.size());
                System.dealloc(ptr, layout);
            }
            new_ptr
        }
    }
}

/// Zero `len` bytes at `ptr` with volatile writes, so the compiler cannot elide
/// the stores as dead (a plain memset before `free` can be removed).
///
/// `write_volatile` is used word at a time where alignment allows — dlmalloc
/// returns at least 8-byte-aligned pointers — with a byte prologue/epilogue for
/// any `Layout::align`.
#[inline]
unsafe fn wipe(ptr: *mut u8, len: usize) {
    unsafe {
        if ptr.is_null() || len == 0 {
            return;
        }

        let mut p = ptr as usize;
        let end = p + len;
        while p % 8 != 0 && p < end {
            core::ptr::write_volatile(p as *mut u8, 0);
            p += 1;
        }
        let words = (end - p) / 8;
        for i in 0..words {
            core::ptr::write_volatile((p + i * 8) as *mut u64, 0);
        }
        p += words * 8;
        while p < end {
            core::ptr::write_volatile(p as *mut u8, 0);
            p += 1;
        }
        compiler_fence(Ordering::SeqCst);
    }
}
