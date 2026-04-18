slint::include_modules!();

mod app;
mod ui;
mod vault;

use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use tokio::runtime::{Builder, Runtime};
use zeroize::Zeroizing;

use app::Vault;
use ui::bridge;
use vault::{crypto, db::Vault as VaultDb, search, Entry, PasswordOptions, VaultError};

const KDF_SALT: &[u8; 16] = b"pass-vault-salt!";
const IDLE_LOCK_SECS: u64 = 300;
const IDLE_CHECK_SECS: u64 = 10;
const CLIPBOARD_AUTOCLEAR_SECS: u64 = 30;

fn main() -> Result<(), slint::PlatformError> {
    // Tokio multi-thread runtime — created manually so `fn main()` stays sync.
    let rt: Arc<Runtime> = Arc::new(
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime"),
    );

    let state = Arc::new(Vault::new());
    let ui = AppWindow::new()?;
    let ui_weak = ui.as_weak();

    // One VecModel owned by main and shared with AppState.entries.
    // Mutated only on the event-loop thread.
    let entries_model: Rc<VecModel<EntryItem>> = Rc::new(VecModel::default());
    ui.global::<AppState>()
        .set_entries(ModelRc::from(entries_model.clone()));

    let last_activity = Arc::new(Mutex::new(Instant::now()));

    register_login(&ui, &state, &entries_model, &rt);
    register_logout(&ui, &state, &entries_model, &rt);
    register_search(&ui, &state, &entries_model);
    register_select_entry(&ui, &state);
    register_save_entry(&ui, &state, &entries_model, &rt);
    register_delete_entry(&ui, &state, &entries_model, &rt);
    register_copy_password(&ui, &state, &rt);
    register_reveal_password(&ui, &state, &entries_model);
    register_new_entry(&ui);
    register_generate_password(&ui);
    register_reset_idle_timer(&ui, &last_activity);

    // Idle-lock timer — `_idle_timer` keeps the Timer alive for the lifetime of main.
    let _idle_timer = start_idle_timer(
        ui_weak.clone(),
        state.clone(),
        entries_model.clone(),
        rt.clone(),
        last_activity,
    );

    // Window close: zeroize session, clear clipboard, hide the window.
    {
        let state = state.clone();
        let rt = rt.clone();
        ui.window().on_close_requested(move || {
            *state.session_key.lock().unwrap() = None;
            *state.all_entries.lock().unwrap() = Vec::new();
            clear_clipboard(&rt);
            slint::CloseRequestResponse::HideWindow
        });
    }

    ui.run()
}

// ── Clipboard ───────────────────────────────────────────────────────────────

/// Write text to the system clipboard from a worker thread.
///
/// On Linux/X11 the selection is owned by the process; if the owner exits the
/// value is lost (without a clipboard manager). We therefore use
/// `SetExtLinux::wait()`, which blocks until another application takes
/// ownership — i.e. until the user pastes elsewhere or `clear_clipboard` runs.
fn write_clipboard(rt: &Runtime, text: String) {
    let _ = rt.spawn_blocking(move || {
        let Ok(mut cb) = arboard::Clipboard::new() else {
            return;
        };
        #[cfg(target_os = "linux")]
        {
            use arboard::SetExtLinux;
            let _ = cb.set().wait().text(text);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cb.set_text(text);
        }
    });
}

fn clear_clipboard(rt: &Runtime) {
    write_clipboard(rt, String::new());
}

// ── Helpers shared across handlers ──────────────────────────────────────────

fn copy_session_key(state: &Vault) -> Option<Zeroizing<[u8; 32]>> {
    let guard = state.session_key.lock().unwrap();
    guard.as_deref().and_then(|k| {
        (k.len() == 32).then(|| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(k);
            Zeroizing::new(arr)
        })
    })
}

fn refill_model(model: &VecModel<EntryItem>, entries: &[Entry]) {
    model.set_vec(entries.iter().map(bridge::entry_to_ui).collect::<Vec<_>>());
}

fn perform_lock(
    state: &Vault,
    entries_model: &VecModel<EntryItem>,
    ui_weak: &slint::Weak<AppWindow>,
    rt: &Runtime,
) {
    *state.session_key.lock().unwrap() = None;
    *state.all_entries.lock().unwrap() = Vec::new();
    clear_clipboard(rt);
    if let Some(ui) = ui_weak.upgrade() {
        entries_model.set_vec(Vec::<EntryItem>::new());
        let app = ui.global::<AppState>();
        app.set_is_logged_in(false);
        app.set_selected_entry_id(-1);
        app.set_error_message(SharedString::default());
        // Mirror to AppWindow until app.slint is migrated to AppState.is-logged-in.
        ui.set_is_locked(true);
    }
}

// ── AppState callback registrations ─────────────────────────────────────────

fn register_login(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
    rt: &Arc<Runtime>,
) {
    let weak = ui.as_weak();
    let state = state.clone();
    let entries_model = entries_model.clone();
    let rt = rt.clone();

    ui.global::<AppState>().on_login(move |password| {
        let weak = weak.clone();
        let state = state.clone();
        let entries_model = entries_model.clone();
        let rt = rt.clone();
        let pwd = password.to_string();

        if let Some(ui) = weak.upgrade() {
            let app = ui.global::<AppState>();
            app.set_is_loading(true);
            app.set_error_message(SharedString::default());
        }

        let _ = slint::spawn_local(async move {
            let outcome = rt
                .spawn_blocking(move || {
                    let key = crypto::derive_key(pwd.as_bytes(), KDF_SALT)?;
                    let vault = VaultDb::open(&key)?;
                    let entries = vault.all_entries()?;
                    Ok::<_, VaultError>((key, vault, entries))
                })
                .await;

            let Some(ui) = weak.upgrade() else { return };
            let app = ui.global::<AppState>();
            app.set_is_loading(false);

            match outcome {
                Ok(Ok((key, vault, entries))) => {
                    *state.vault.lock().unwrap() = Some(vault);
                    *state.session_key.lock().unwrap() =
                        Some(Zeroizing::new(key.to_vec()));
                    *state.all_entries.lock().unwrap() = entries.clone();
                    refill_model(&entries_model, &entries);
                    app.set_is_logged_in(true);
                    app.set_error_message(SharedString::default());
                    // Mirror to AppWindow until app.slint is migrated.
                    ui.set_is_locked(false);
                }
                Ok(Err(e)) => app.set_error_message(e.to_string().into()),
                Err(e) => app.set_error_message(format!("internal error: {e}").into()),
            }
        });
    });
}

fn register_logout(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
    rt: &Arc<Runtime>,
) {
    let weak = ui.as_weak();
    let state = state.clone();
    let entries_model = entries_model.clone();
    let rt = rt.clone();

    ui.global::<AppState>().on_logout(move || {
        perform_lock(&state, &entries_model, &weak, &rt);
    });
}

fn register_search(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
) {
    let state = state.clone();
    let entries_model = entries_model.clone();

    ui.global::<AppState>().on_search_changed(move |query| {
        let entries = state.all_entries.lock().unwrap();
        let filtered = search::filter_entries(&entries, query.as_str());
        refill_model(&entries_model, &filtered);
    });
}

fn register_select_entry(ui: &AppWindow, state: &Arc<Vault>) {
    let weak = ui.as_weak();
    let state = state.clone();

    ui.global::<AppState>().on_select_entry(move |id| {
        let Some(ui) = weak.upgrade() else { return };
        let app = ui.global::<AppState>();
        if id < 0 {
            app.set_selected_entry_id(-1);
            return;
        }
        let entries = state.all_entries.lock().unwrap();
        if let Some(entry) = entries.iter().find(|e| e.id == id as u32) {
            app.set_selected_entry_id(id);
            app.set_selected_entry(bridge::entry_to_ui(entry));
            app.set_detail_mode("view".into());
        }
    });
}

fn register_save_entry(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
    rt: &Arc<Runtime>,
) {
    let weak = ui.as_weak();
    let state = state.clone();
    let entries_model = entries_model.clone();
    let rt = rt.clone();

    ui.global::<AppState>().on_save_entry(move |ui_entry| {
        let weak = weak.clone();
        let state = state.clone();
        let entries_model = entries_model.clone();
        let rt = rt.clone();

        let key = match copy_session_key(&state) {
            Some(k) => k,
            None => {
                if let Some(ui) = weak.upgrade() {
                    ui.global::<AppState>()
                        .set_error_message("Сесія заблокована".into());
                }
                return;
            }
        };

        let entry = bridge::ui_to_entry(&ui_entry);
        let password = ui_entry.password.to_string();
        let entry_id = entry.id;

        if let Some(ui) = weak.upgrade() {
            ui.global::<AppState>().set_is_loading(true);
        }

        let _ = slint::spawn_local(async move {
            let outcome = rt
                .spawn_blocking(move || {
                    let blob = if password.is_empty() && entry_id > 0 {
                        let guard = state.vault.lock().unwrap();
                        let v = guard.as_ref().ok_or(VaultError::SessionLocked)?;
                        v.get_encrypted_password(entry_id)?
                    } else {
                        crypto::encrypt(password.as_bytes(), &*key)?
                    };

                    let entries = {
                        let guard = state.vault.lock().unwrap();
                        let v = guard.as_ref().ok_or(VaultError::SessionLocked)?;
                        v.save_entry(&entry, &blob)?;
                        v.all_entries()?
                    };
                    *state.all_entries.lock().unwrap() = entries.clone();
                    Ok::<_, VaultError>(entries)
                })
                .await;

            let Some(ui) = weak.upgrade() else { return };
            let app = ui.global::<AppState>();
            app.set_is_loading(false);

            match outcome {
                Ok(Ok(entries)) => {
                    refill_model(&entries_model, &entries);
                    app.set_selected_entry_id(-1);
                    app.set_detail_mode("view".into());
                    app.set_error_message(SharedString::default());
                }
                Ok(Err(e)) => app.set_error_message(e.to_string().into()),
                Err(e) => app.set_error_message(format!("internal error: {e}").into()),
            }
        });
    });
}

fn register_delete_entry(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
    rt: &Arc<Runtime>,
) {
    let weak = ui.as_weak();
    let state = state.clone();
    let entries_model = entries_model.clone();
    let rt = rt.clone();

    ui.global::<AppState>().on_delete_entry(move |id| {
        if id < 0 {
            return;
        }
        let weak = weak.clone();
        let state = state.clone();
        let entries_model = entries_model.clone();
        let rt = rt.clone();

        if let Some(ui) = weak.upgrade() {
            ui.global::<AppState>().set_is_loading(true);
        }

        let _ = slint::spawn_local(async move {
            let outcome = rt
                .spawn_blocking(move || {
                    let entries = {
                        let guard = state.vault.lock().unwrap();
                        let v = guard.as_ref().ok_or(VaultError::SessionLocked)?;
                        v.delete_entry(id as u32)?;
                        v.all_entries()?
                    };
                    *state.all_entries.lock().unwrap() = entries.clone();
                    Ok::<_, VaultError>(entries)
                })
                .await;

            let Some(ui) = weak.upgrade() else { return };
            let app = ui.global::<AppState>();
            app.set_is_loading(false);

            match outcome {
                Ok(Ok(entries)) => {
                    refill_model(&entries_model, &entries);
                    app.set_selected_entry_id(-1);
                    app.set_detail_mode("view".into());
                }
                Ok(Err(e)) => app.set_error_message(e.to_string().into()),
                Err(e) => app.set_error_message(format!("internal error: {e}").into()),
            }
        });
    });
}

fn register_copy_password(ui: &AppWindow, state: &Arc<Vault>, rt: &Arc<Runtime>) {
    let state = state.clone();
    let rt = rt.clone();

    ui.global::<AppState>().on_copy_password(move |id| {
        if id < 0 {
            return;
        }
        let Some(key) = copy_session_key(&state) else {
            return;
        };

        let plain = {
            let guard = state.vault.lock().unwrap();
            let Some(v) = guard.as_ref() else { return };
            match v
                .get_encrypted_password(id as u32)
                .and_then(|blob| crypto::decrypt(&blob, &*key))
            {
                Ok(bytes) => bytes,
                Err(_) => return,
            }
        };

        let pwd = String::from_utf8_lossy(&plain).into_owned();
        write_clipboard(&rt, pwd);

        // Auto-clear after the timeout. Timer fires on the event loop;
        // clear_clipboard hops back to a worker thread.
        let rt_clear = rt.clone();
        slint::Timer::single_shot(
            Duration::from_secs(CLIPBOARD_AUTOCLEAR_SECS),
            move || clear_clipboard(&rt_clear),
        );
    });
}

fn register_reveal_password(
    ui: &AppWindow,
    state: &Arc<Vault>,
    entries_model: &Rc<VecModel<EntryItem>>,
) {
    let weak = ui.as_weak();
    let state = state.clone();
    let entries_model = entries_model.clone();

    ui.global::<AppState>().on_reveal_password(move |id| {
        if id < 0 {
            return;
        }
        let Some(key) = copy_session_key(&state) else {
            return;
        };

        let plain = {
            let guard = state.vault.lock().unwrap();
            let Some(v) = guard.as_ref() else { return };
            match v
                .get_encrypted_password(id as u32)
                .and_then(|blob| crypto::decrypt(&blob, &*key))
            {
                Ok(bytes) => bytes,
                Err(_) => return,
            }
        };

        let pwd: SharedString = String::from_utf8_lossy(&plain).as_ref().into();

        for i in 0..entries_model.row_count() {
            if let Some(mut item) = entries_model.row_data(i) {
                if item.id == id {
                    item.password = pwd.clone();
                    entries_model.set_row_data(i, item);
                    break;
                }
            }
        }

        if let Some(ui) = weak.upgrade() {
            let app = ui.global::<AppState>();
            let mut sel = app.get_selected_entry();
            if sel.id == id {
                sel.password = pwd;
                app.set_selected_entry(sel);
            }
        }
    });
}

fn register_new_entry(ui: &AppWindow) {
    let weak = ui.as_weak();
    ui.global::<AppState>().on_new_entry_requested(move || {
        if let Some(ui) = weak.upgrade() {
            let app = ui.global::<AppState>();
            app.set_selected_entry_id(-1);
            app.set_selected_entry(EntryItem::default());
            app.set_detail_mode("new".into());
        }
    });
}

fn register_generate_password(ui: &AppWindow) {
    ui.global::<AppState>().on_generate_password(
        |length, uppercase, digits, symbols, exclude_ambiguous| -> SharedString {
            let opts = PasswordOptions {
                length: length.max(8) as usize,
                uppercase,
                digits,
                symbols,
                exclude_ambiguous,
            };
            crypto::generate_password(&opts).into()
        },
    );
}

fn register_reset_idle_timer(ui: &AppWindow, last_activity: &Arc<Mutex<Instant>>) {
    let last_activity = last_activity.clone();
    ui.global::<AppState>().on_reset_idle_timer(move || {
        *last_activity.lock().unwrap() = Instant::now();
    });
}

fn start_idle_timer(
    ui_weak: slint::Weak<AppWindow>,
    state: Arc<Vault>,
    entries_model: Rc<VecModel<EntryItem>>,
    rt: Arc<Runtime>,
    last_activity: Arc<Mutex<Instant>>,
) -> slint::Timer {
    let timer = slint::Timer::default();
    timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(IDLE_CHECK_SECS),
        move || {
            if last_activity.lock().unwrap().elapsed()
                < Duration::from_secs(IDLE_LOCK_SECS)
            {
                return;
            }
            // Idempotent: skip if already locked.
            if state.session_key.lock().unwrap().is_none() {
                return;
            }
            perform_lock(&state, &entries_model, &ui_weak, &rt);
        },
    );
    timer
}
