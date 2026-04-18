use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::time;

slint::include_modules!();

mod app;
mod ui;
mod vault;

fn main() -> Result<(), slint::PlatformError> {
    // 1. Tokio runtime — not #[tokio::main]
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap(),
    );

    // 2. AppState and window
    let state = app::AppState::new();
    let window = AppWindow::new()?;

    // Bind entries model to UI before handlers run
    window.set_entries(slint::ModelRc::from(state.entries_model.clone()));

    // 3. Register all event handlers
    ui::handlers::register_all(&window, &state, rt.clone());

    // 4. Auto-lock idle timer
    //    Track the last user interaction time; check every 10 s; lock after 5 min.
    let last_activity = Arc::new(Mutex::new(Instant::now()));

    let la_check = last_activity.clone();
    let weak_lock = window.as_weak();
    let session_key_lock = state.session_key.clone();
    let all_entries_lock = state.all_entries.clone();

    let _idle_timer = slint::Timer::default();
    _idle_timer.start(
        slint::TimerMode::Repeated,
        Duration::from_secs(10),
        move || {
            if la_check.lock().unwrap().elapsed() >= Duration::from_secs(300) {
                // Check if session is already locked to avoid redundant work
                let already_locked = session_key_lock.lock().unwrap().is_none();
                if !already_locked {
                    *session_key_lock.lock().unwrap() = None;
                    *all_entries_lock.lock().unwrap() = Vec::new();
                    if let Ok(cb) = arboard::Clipboard::new() {
                        let _ = cb.set_text("");
                        // Keep clipboard alive briefly
                        tokio::spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            drop(cb);
                        });
                    }
                    // Timer callback is already in event loop — use upgrade(), not upgrade_in_event_loop
                    if let Some(ui) = weak_lock.upgrade() {
                        ui.set_is_locked(true);
                        ui.set_entries(slint::ModelRc::from(std::rc::Rc::new(
                            slint::VecModel::<EntryItem>::default(),
                        )));
                        ui.set_selected_entry_id(-1);
                    }
                }
            }
        },
    );

    // 5. Reset idle timer on any user activity
    window.on_reset_idle_timer({
        let la = last_activity.clone();
        move || {
            *la.lock().unwrap() = Instant::now();
        }
    });

    // 6. Window close handler — zeroize session key before hiding
    let session_key_close = state.session_key.clone();
    window.window().on_close_requested(move || {
        *session_key_close.lock().unwrap() = None;
        if let Ok(cb) = arboard::Clipboard::new() {
            let _ = cb.set_text("");
            // Keep clipboard alive briefly
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                drop(cb);
            });
        }
        slint::CloseRequestResponse::HideWindow
    });

    window.run()
}
