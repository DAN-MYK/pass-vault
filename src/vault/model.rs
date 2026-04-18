use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entry {
    pub id: u32,
    pub title: String,
    pub username: String,
    pub url: String,
    pub notes: Option<String>,
    pub category_id: u32,
    pub favorite: bool,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    // password НЕ зберігається тут відкрито — окремий decrypt_password()
}

#[allow(dead_code)] // будуть використані при реалізації категорій
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Category {
    pub id: u32,
    pub name: String,
    pub icon: String,
}

#[derive(Debug)]
pub enum VaultError {
    Io(std::io::Error),
    Db(rusqlite::Error),
    Crypto(String),
    NotFound(u32),
    SessionLocked,
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "IO error: {e}"),
            VaultError::Db(e) => write!(f, "Database error: {e}"),
            VaultError::Crypto(msg) => write!(f, "Crypto error: {msg}"),
            VaultError::NotFound(id) => write!(f, "Entry not found: {id}"),
            VaultError::SessionLocked => write!(f, "Session is locked"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<std::io::Error> for VaultError {
    fn from(e: std::io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        VaultError::Db(e)
    }
}

pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 16,
            uppercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
        }
    }
}
