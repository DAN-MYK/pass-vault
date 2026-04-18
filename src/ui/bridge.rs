use slint::SharedString;

use crate::vault::model::Entry;
use crate::EntryItem;

pub fn entry_to_ui(e: &Entry) -> EntryItem {
    EntryItem {
        id: e.id as i32,
        title: e.title.as_str().into(),
        username: e.username.as_str().into(),
        url: e.url.as_str().into(),
        password: SharedString::default(),
        notes: e.notes.as_deref().unwrap_or("").into(),
        category: SharedString::default(),
        favorite: e.favorite,
        updated_at: e.updated_at.format("%Y-%m-%d").to_string().into(),
    }
}

pub fn ui_to_entry(item: &EntryItem) -> Entry {
    Entry {
        id: item.id as u32,
        title: item.title.to_string(),
        username: item.username.to_string(),
        url: item.url.to_string(),
        notes: {
            let s = item.notes.to_string();
            if s.is_empty() { None } else { Some(s) }
        },
        category_id: 0,
        favorite: item.favorite,
        updated_at: chrono::DateTime::default(),
    }
}
