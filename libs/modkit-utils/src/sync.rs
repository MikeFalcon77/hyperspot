use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Convenience extension for `std::sync::Mutex` that unwraps the `LockResult`.
///
/// Wraps `lock().unwrap()` to keep call sites clean under strict clippy
/// (`unwrap_used`, `expect_used`, `missing_panics_doc`).
pub trait MutexExt<T> {
    /// Lock the mutex, panicking on poison.
    fn hold(&self) -> MutexGuard<'_, T>;

    /// Get exclusive access without locking (requires `&mut self`), panicking on poison.
    fn hold_mut(&mut self) -> &mut T;
}

impl<T> MutexExt<T> for Mutex<T> {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn hold(&self) -> MutexGuard<'_, T> {
        self.lock().unwrap()
    }

    #[allow(clippy::unwrap_used)]
    #[inline]
    fn hold_mut(&mut self) -> &mut T {
        self.get_mut().unwrap()
    }
}

/// Convenience extension for `std::sync::RwLock` that unwraps the `LockResult`.
pub trait RwLockExt<T> {
    /// Acquire a shared read lock, panicking on poison.
    fn hold_read(&self) -> RwLockReadGuard<'_, T>;

    /// Acquire an exclusive write lock, panicking on poison.
    fn hold_write(&self) -> RwLockWriteGuard<'_, T>;
}

impl<T> RwLockExt<T> for RwLock<T> {
    #[allow(clippy::unwrap_used)]
    #[inline]
    fn hold_read(&self) -> RwLockReadGuard<'_, T> {
        self.read().unwrap()
    }

    #[allow(clippy::unwrap_used)]
    #[inline]
    fn hold_write(&self) -> RwLockWriteGuard<'_, T> {
        self.write().unwrap()
    }
}
