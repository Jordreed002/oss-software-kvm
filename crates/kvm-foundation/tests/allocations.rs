//! Counting allocator exists only in this test binary. Production foundation
//! code remains unsafe-free. Counting is thread-local to exclude test-harness
//! allocations on other threads.
#![allow(unsafe_code)]

use kvm_foundation::RingFifo;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static COUNT: Cell<usize> = const { Cell::new(0) };
}

fn record() {
    let _ = COUNTING.try_with(|enabled| {
        if enabled.get() {
            let _ = COUNT.try_with(|count| count.set(count.get() + 1));
        }
    });
}

struct CountingAllocator;

// SAFETY: every operation delegates unchanged pointers/layouts to System;
// instrumentation uses const-initialized TLS Cells and never allocates.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forwarded under the caller's GlobalAlloc contract.
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record();
        // SAFETY: forwarded under the caller's GlobalAlloc contract.
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record();
        // SAFETY: forwarded under the caller's GlobalAlloc contract.
        unsafe { System.realloc(pointer, layout, size) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        // SAFETY: forwarded under the caller's GlobalAlloc contract.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn queue_construction_and_steady_state_allocate_nothing() {
    COUNT.with(|count| count.set(0));
    COUNTING.with(|enabled| enabled.set(true));
    let control = black_box(Vec::<u32>::with_capacity(black_box(16)));
    black_box(&control);
    COUNTING.with(|enabled| enabled.set(false));
    let control_allocations = COUNT.with(Cell::get);
    assert!(
        control_allocations > 0,
        "allocator instrumentation must detect a heap allocation"
    );
    drop(control);

    COUNT.with(|count| count.set(0));
    COUNTING.with(|enabled| enabled.set(true));
    let mut queue = black_box(RingFifo::<u32, 256>::new());
    let mut correct = true;
    for value in 0..100_000 {
        correct &= black_box(&mut queue).push(black_box(value)).is_ok();
        correct &= black_box(&mut queue).pop() == Some(value);
    }
    for value in 0..256 {
        correct &= queue.push(value).is_ok();
    }
    correct &= queue.push(256) == Err(256);
    for value in 0..256 {
        correct &= queue.pop() == Some(value);
    }
    COUNTING.with(|enabled| enabled.set(false));
    let allocations = COUNT.with(Cell::get);
    assert!(correct);
    assert_eq!(allocations, 0);
}
