use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use slint::{ComponentHandle, Model, VecModel};
use tokio::runtime::Runtime;
use zeroize::Zeroizing;

use crate::app::AppState;
use crate::ui::bridge;
use crate::vault::crypto;
use crate::vault::VaultError;
use crate::{AppWindow, EntryItem};

pub fn register_all(ui: &AppWindow, state: &AppState, _rt: Arc<Runtime>) {
    register_login(ui, state);
    register_search_changed(ui, state);
    register_entry_selected(ui, state);
    register_entry_save(ui, state);
    register_entry_delete(ui, state);
    register_entry_copy_password(ui, state);
    register_reveal_password(ui, state);
    register_lock_requested(ui, state);
    register_new_entry_requested(ui);
    register_generate_password(ui);
}

// Helper: copy session key into a Zeroizing [u8;32]
fn copy_key(
    session_key: &Arc<Mutex<Option<Zeroizing<Vec<u8>>>>>,
) -> Option<Zeroizing<[u8; 32]>> {
    let guard = session_key.lock().unwrap();
    guard.as_deref().and_then(|k| {
        if k.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(k);
            Some(Zeroizing::new(arr))
        } else {
            None
        }
    })
}

fn register_login(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let vault_arc = state.vault.clone();
    let session_key = state.session_key.clone();
    let all_entries = state.all_entries.clone();

    ui.on_login(move |master_password| {
        let password = master_password.to_string();
        let weak = weak.clone();
        let vault_arc = vault_arc.clone();
        let session_key = session_key.clone();
        let all_entries = all_entries.clone();

        if let Some(ui) = weak.upgrade() {
            ui.set_is_loading(true);
            ui.set_error_message(Default::default());
        }

        std::thread::spawn(move || {
            let salt = b"pass-vault-salt!"; // TODO: per-db salt stored in metadata
            match crypto::derive_key(password.as_bytes(), salt) {
                Ok(key) => match crate::vault::db::Vault::open(&key) {
                    Ok(vault) => {
                        let entries = vault.all_entries().unwrap_or_default();
                        *vault_arc.lock().unwrap() = Some(vault);
                        *session_key.lock().unwrap() =
                            Some(Zeroizing::new(key.to_vec()));
                        *all_entries.lock().unwrap() = entries.clone();

                        weak.upgrade_in_event_loop(move |ui| {
                            let model = bridge::entries_to_model(&entries);
                            ui.set_entries(slint::ModelRc::from(model));
                            ui.set_is_locked(false);
                            ui.set_is_loading(false);
                            ui.set_error_message(Default::default());
                        })
                        .ok();
                    }
                    Err(e) => {
                        weak.upgrade_in_event_loop(move |ui| {
                            ui.set_is_loading(false);
                            ui.set_error_message(e.to_string().into());
                        })
                        .ok();
                    }
                },
                Err(e) => {
                    weak.upgrade_in_event_loop(move |ui| {
                        ui.set_is_loading(false);
                        ui.set_error_message(e.to_string().into());
                    })
                    .ok();
                }
            }
        });
    });
}

fn register_search_changed(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let all_entries = state.all_entries.clone();

    ui.on_search_changed(move |query| {
        let entries = all_entries.lock().unwrap();
        let filtered = crate::vault::search::filter_entries(&entries, query.as_str());
        let model = bridge::entries_to_model(&filtered);
        if let Some(ui) = weak.upgrade() {
            ui.set_entries(slint::ModelRc::from(model));
        }
    });
}

fn register_entry_selected(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let all_entries = state.all_entries.clone();

    ui.on_entry_selected(move |id| {
        let Some(ui) = weak.upgrade() else { return };
        if id < 0 {
            ui.set_selected_entry_id(-1);
            return;
        }
        let entries = all_entries.lock().unwrap();
        if let Some(entry) = entries.iter().find(|e| e.id == id as u32) {
            ui.set_selected_entry_id(id);
            ui.set_selected_entry(bridge::entry_to_ui(entry));
            ui.set_detail_mode("view".into());
        }
    });
}

fn register_entry_save(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let vault_arc = state.vault.clone();
    let session_key = state.session_key.clone();
    let all_entries = state.all_entries.clone();

    ui.on_entry_save(move |ui_entry| {
        let rust_entry = bridge::ui_to_entry(&ui_entry);
        let password_str = ui_entry.password.to_string();
        let entry_id = ui_entry.id;

        let key = match copy_key(&session_key) {
            Some(k) => k,
            None => {
                if let Some(ui) = weak.upgrade() {
                    ui.set_error_message("Сесія заблокована".into());
                }
                return;
            }
        };

        if let Some(ui) = weak.upgrade() {
            ui.set_is_loading(true);
        }

        let weak2 = weak.clone();
        let vault2 = vault_arc.clone();
        let all_entries2 = all_entries.clone();

        std::thread::spawn(move || {
            // If editing an existing entry and password field is empty, keep the existing
            // encrypted password from the DB; otherwise encrypt the new password.
            let encrypted_result: Result<Vec<u8>, VaultError> = if password_str.is_empty()
                && entry_id > 0
            {
                let guard = vault2.lock().unwrap();
                match guard.as_ref() {
                    Some(v) => v.get_encrypted_password(entry_id as u32),
                    None => Err(VaultError::SessionLocked),
                }
            } else {
                crypto::encrypt(password_str.as_bytes(), &*key)
            };

            let encrypted = match encrypted_result {
                Ok(e) => e,
                Err(e) => {
                    weak2
                        .upgrade_in_event_loop(move |ui| {
                            ui.set_is_loading(false);
                            ui.set_error_message(e.to_string().into());
                        })
                        .ok();
                    return;
                }
            };

            let result = {
                let guard = vault2.lock().unwrap();
                match guard.as_ref() {
                    Some(v) => v
                        .save_entry(&rust_entry, &encrypted)
                        .and_then(|_| v.all_entries()),
                    None => Err(VaultError::SessionLocked),
                }
            };

            match result {
                Ok(entries) => {
                    *all_entries2.lock().unwrap() = entries.clone();
                    weak2
                        .upgrade_in_event_loop(move |ui| {
                            let model = bridge::entries_to_model(&entries);
                            ui.set_entries(slint::ModelRc::from(model));
                            ui.set_is_loading(false);
                            ui.set_selected_entry_id(-1);
                            ui.set_detail_mode("view".into());
                            ui.set_error_message(Default::default());
                        })
                        .ok();
                }
                Err(e) => {
                    weak2
                        .upgrade_in_event_loop(move |ui| {
                            ui.set_is_loading(false);
                            ui.set_error_message(e.to_string().into());
                        })
                        .ok();
                }
            }
        });
    });
}

fn register_entry_delete(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let vault_arc = state.vault.clone();
    let all_entries = state.all_entries.clone();

    ui.on_entry_delete(move |id| {
        if id < 0 {
            return;
        }

        if let Some(ui) = weak.upgrade() {
            ui.set_is_loading(true);
        }

        let weak2 = weak.clone();
        let vault2 = vault_arc.clone();
        let all_entries2 = all_entries.clone();

        std::thread::spawn(move || {
            let result = {
                let guard = vault2.lock().unwrap();
                match guard.as_ref() {
                    Some(v) => v.delete_entry(id as u32).and_then(|_| v.all_entries()),
                    None => Err(VaultError::SessionLocked),
                }
            };

            match result {
                Ok(entries) => {
                    *all_entries2.lock().unwrap() = entries.clone();
                    weak2
                        .upgrade_in_event_loop(move |ui| {
                            let model = bridge::entries_to_model(&entries);
                            ui.set_entries(slint::ModelRc::from(model));
                            ui.set_is_loading(false);
                            ui.set_selected_entry_id(-1);
                            ui.set_detail_mode("view".into());
                        })
                        .ok();
                }
                Err(e) => {
                    weak2
                        .upgrade_in_event_loop(move |ui| {
                            ui.set_is_loading(false);
                            ui.set_error_message(e.to_string().into());
                        })
                        .ok();
                }
            }
        });
    });
}

fn register_entry_copy_password(ui: &AppWindow, state: &AppState) {
    let vault_arc = state.vault.clone();
    let session_key = state.session_key.clone();

    ui.on_entry_copy_password(move |id| {
        if id < 0 {
            return;
        }

        let key = match copy_key(&session_key) {
            Some(k) => k,
            None => return,
        };

        let result = {
            let guard = vault_arc.lock().unwrap();
            match guard.as_ref() {
                Some(v) => v
                    .get_encrypted_password(id as u32)
                    .and_then(|blob| crypto::decrypt(&blob, &*key)),
                None => return,
            }
        };

        if let Ok(pwd_bytes) = result {
            let pwd = String::from_utf8_lossy(&pwd_bytes).to_string();
            if let Ok(mut cb) = arboard::Clipboard::new() {
                let _ = cb.set_text(&pwd);
                // Keep clipboard alive for at least 900ms to avoid "dropped too quickly" warning
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(900)).await;
                    drop(cb);
                });
            }
            // Auto-clear after 30 seconds — Timer callback is already in event loop
            slint::Timer::single_shot(Duration::from_secs(30), move || {
                if let Ok(mut cb) = arboard::Clipboard::new() {
                    let _ = cb.set_text("");
                    // Keep clipboard alive for at least 800ms
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
                        drop(cb);
                    });
                }
            });
        }
    });
}

fn register_reveal_password(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let vault_arc = state.vault.clone();
    let session_key = state.session_key.clone();

    ui.on_reveal_password(move |id| {
        if id < 0 {
            return;
        }

        let key = match copy_key(&session_key) {
            Some(k) => k,
            None => return,
        };

        let result = {
            let guard = vault_arc.lock().unwrap();
            match guard.as_ref() {
                Some(v) => v
                    .get_encrypted_password(id as u32)
                    .and_then(|blob| crypto::decrypt(&blob, &*key)),
                None => return,
            }
        };

        if let Ok(pwd_bytes) = result {
            let pwd_shared: slint::SharedString =
                String::from_utf8_lossy(&pwd_bytes).as_ref().into();
            if let Some(ui) = weak.upgrade() {
                // Update the matching entry in the current model so the UI can display it
                let model = ui.get_entries();
                for i in 0..model.row_count() {
                    if let Some(mut item) = model.row_data(i) {
                        if item.id == id {
                            item.password = pwd_shared;
                            model.set_row_data(i, item);
                            break;
                        }
                    }
                }
            }
        }
    });
}

fn register_lock_requested(ui: &AppWindow, state: &AppState) {
    let weak = ui.as_weak();
    let session_key = state.session_key.clone();
    let all_entries = state.all_entries.clone();

    ui.on_lock_requested(move || {
        // Zeroize and drop the session key
        *session_key.lock().unwrap() = None;
        // Clear cached entries
        *all_entries.lock().unwrap() = Vec::new();
        // Clear clipboard on lock
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text("");
            // Keep clipboard alive briefly
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                drop(cb);
            });
        }
        if let Some(ui) = weak.upgrade() {
            ui.set_is_locked(true);
            ui.set_entries(slint::ModelRc::from(Rc::new(
                VecModel::<EntryItem>::default(),
            )));
            ui.set_selected_entry_id(-1);
            ui.set_error_message(Default::default());
        }
    });
}

fn register_new_entry_requested(ui: &AppWindow) {
    let weak = ui.as_weak();

    ui.on_new_entry_requested(move || {
        if let Some(ui) = weak.upgrade() {
            ui.set_selected_entry_id(-1);
        }
    });
}

fn register_generate_password(ui: &AppWindow) {
    ui.on_generate_password(
        |length, uppercase, digits, symbols, excl_ambiguous| -> slint::SharedString {
            let opts = crate::vault::PasswordOptions {
                length: length.max(8) as usize,
                uppercase,
                digits,
                symbols,
                exclude_ambiguous: excl_ambiguous,
            };
            crypto::generate_password(&opts).into()
        },
    );
}
