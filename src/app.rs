use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::vault::db::Vault as VaultDb;
use crate::vault::VaultError;

/// Runtime app state shared across the event loop and worker threads.
/// Distinct from the Slint-generated `AppState` global, which holds UI
/// properties and callbacks. `Vault` here owns the DB handle, the in-memory
/// session key, and the cached entry list.
pub struct Vault {
    pub vault: Arc<Mutex<Option<VaultDb>>>,
    pub session_key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    pub all_entries: Arc<Mutex<Vec<crate::vault::Entry>>>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(None)),
            session_key: Arc::new(Mutex::new(None)),
            all_entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_key(&self, key: [u8; 32]) {
        let mut guard = self.session_key.lock().unwrap();
        *guard = Some(Zeroizing::new(key.to_vec()));
    }

    pub fn lock_session(&self) {
        let mut guard = self.session_key.lock().unwrap();
        *guard = None;
    }

    pub fn with_key<F, R>(&self, f: F) -> Result<R, VaultError>
    where
        F: FnOnce(&[u8]) -> R,
    {
        let guard = self.session_key.lock().unwrap();
        match guard.as_deref() {
            Some(key) => Ok(f(key)),
            None => Err(VaultError::SessionLocked),
        }
    }
}
