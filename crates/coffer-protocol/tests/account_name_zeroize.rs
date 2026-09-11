// Coffer: a native Linux client for Apple Passwords.
// Copyright (C) 2026  Hong Minhee
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Regression coverage for wiping account-name allocations before release.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering};

use coffer_protocol::secret::{AccountName, InvalidAccountName, MAX_ACCOUNT_NAME_LEN};

const IDLE: u8 = 0;
const WATCHING: u8 = 1;
const ZEROIZED: u8 = 2;
const NOT_ZEROIZED: u8 = 3;

static WATCHED_POINTER: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
static WATCHED_CAPACITY: AtomicUsize = AtomicUsize::new(0);
static OBSERVATION: AtomicU8 = AtomicU8::new(IDLE);

struct InspectingAllocator;

#[global_allocator]
static ALLOCATOR: InspectingAllocator = InspectingAllocator;

#[allow(
    unsafe_code,
    reason = "the allocation must be inspected while it is still valid in dealloc"
)]
// SAFETY: every allocation operation delegates to `System` with unchanged
// arguments. `dealloc` only observes the still-valid watched allocation before
// delegating its release with the original pointer and layout.
unsafe impl GlobalAlloc for InspectingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: This allocator delegates the request unchanged to `System`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if WATCHED_POINTER
            .compare_exchange(pointer, ptr::null_mut(), Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let capacity = WATCHED_CAPACITY.load(Ordering::SeqCst);
            // SAFETY: The watched pointer and capacity come from this exact
            // allocation, and `dealloc` has not released it yet.
            let bytes = unsafe { std::slice::from_raw_parts(pointer, capacity) };
            let result = if bytes.iter().all(|byte| *byte == 0) {
                ZEROIZED
            } else {
                NOT_ZEROIZED
            };
            OBSERVATION.store(result, Ordering::SeqCst);
        }

        // SAFETY: This is the same pointer and layout supplied by the caller
        // to the allocator that delegated allocation to `System`.
        unsafe { System.dealloc(pointer, layout) }
    }
}

fn watch(input: &mut String) {
    assert_ne!(input.capacity(), 0);
    assert_eq!(OBSERVATION.swap(WATCHING, Ordering::SeqCst), IDLE);
    WATCHED_CAPACITY.store(input.capacity(), Ordering::SeqCst);
    WATCHED_POINTER.store(input.as_mut_ptr(), Ordering::SeqCst);
}

fn assert_zeroized() {
    assert_eq!(OBSERVATION.swap(IDLE, Ordering::SeqCst), ZEROIZED);
    assert!(WATCHED_POINTER.load(Ordering::SeqCst).is_null());
}

fn assert_rejected_and_zeroized(mut input: String, expected: InvalidAccountName) {
    watch(&mut input);
    assert_eq!(AccountName::new(input).unwrap_err(), expected);
    assert_zeroized();
}

#[test]
fn account_name_zeroizes_owned_allocation_on_every_exit() {
    let mut accepted = "synthetic-account".to_owned();
    watch(&mut accepted);
    let accepted = AccountName::new(accepted).unwrap();
    assert_eq!(OBSERVATION.load(Ordering::SeqCst), WATCHING);
    drop(accepted);
    assert_zeroized();

    assert_rejected_and_zeroized(
        "x".repeat(MAX_ACCOUNT_NAME_LEN + 1),
        InvalidAccountName::TooLong,
    );
    assert_rejected_and_zeroized(
        "synthetic\raccount".to_owned(),
        InvalidAccountName::ControlCharacter,
    );

    let mut empty_with_stale_capacity = "stale-synthetic-input".to_owned();
    empty_with_stale_capacity.clear();
    assert_rejected_and_zeroized(empty_with_stale_capacity, InvalidAccountName::Empty);
}
