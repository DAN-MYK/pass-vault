use std::rc::Rc;
use std::sync::{Arc, Mutex};

use slint::VecModel;
use zeroize::Zeroizing;

use crate::vault::db::Vault;
use crate::vault::VaultError;
use crate::CategoryItem;

pub struct AppState {
    pub vault: Arc<Mutex<Option<Vault>>>,
    #[allow(dead_code)] // будуть використані при реалізації категорій
    pub categories_model: Rc<VecModel<CategoryItem>>,
    pub session_key: Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
    pub all_entries: Arc<Mutex<Vec<crate::vault::Entry>>>,
}

impl AppState {
    pub fn new() -> Self {
        Self {
            vault: Arc::new(Mutex::new(None)),
            categories_model: Rc::new(VecModel::default()),
            session_key: Arc::new(Mutex::new(None)),
            all_entries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    #[allow(dead_code)]
    pub fn set_key(&self, key: [u8; 32]) {
        let mut guard = self.session_key.lock().unwrap();
        *guard = Some(Zeroizing::new(key.to_vec()));
    }

    #[allow(dead_code)]
    pub fn lock_session(&self) {
        let mut guard = self.session_key.lock().unwrap();
        *guard = None;
    }

    #[allow(dead_code)]
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
