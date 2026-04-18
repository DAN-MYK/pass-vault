use chrono::{DateTime, Utc};

use crate::vault::model::{Category, Entry, VaultError};
use rand::RngCore;
use rusqlite::Connection;
use std::path::PathBuf;

fn parse_datetime(s: String) -> DateTime<Utc> {
    s.parse::<DateTime<Utc>>().unwrap_or_default()
}

pub struct Vault {
    conn: Connection,
}

impl Vault {
    pub fn open(master_key: &[u8; 32]) -> Result<Self, VaultError> {
        let db_path = Self::db_path()?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(&db_path)?;

        // SQLCipher: встановити ключ шифрування БД
        let hex_key = hex::encode(master_key);
        conn.pragma_update(None, "key", &format!("x'{hex_key}'"))?;

        let vault = Self { conn };
        vault.migrate()?;
        Ok(vault)
    }

    fn db_path() -> Result<PathBuf, VaultError> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| VaultError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "cannot determine data directory",
            )))?;
        Ok(data_dir.join("pass-vault").join("vault.db"))
    }

    fn salt_path() -> Result<PathBuf, VaultError> {
        Ok(Self::db_path()?.with_extension("salt"))
    }

    pub fn load_or_create_salt() -> Result<[u8; 32], VaultError> {
        let path = Self::salt_path()?;
        if path.exists() {
            let bytes = std::fs::read(&path)?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(arr);
            }
        }
        // Generate new salt
        let mut salt = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &salt)?;
        Ok(salt)
    }

    fn migrate(&self) -> Result<(), VaultError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS categories (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                name  TEXT NOT NULL,
                icon  TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS entries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                username    TEXT NOT NULL DEFAULT '',
                url         TEXT NOT NULL DEFAULT '',
                password    BLOB NOT NULL,
                notes       TEXT,
                category_id INTEGER NOT NULL DEFAULT 0,
                favorite    INTEGER NOT NULL DEFAULT 0,
                updated_at  TEXT NOT NULL,
                FOREIGN KEY (category_id) REFERENCES categories(id)
            );

            INSERT OR IGNORE INTO categories (id, name, icon) VALUES (0, 'Uncategorized', '');",
        )?;
        Ok(())
    }

    pub fn all_entries(&self) -> Result<Vec<Entry>, VaultError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, username, url, notes, category_id, favorite, updated_at
             FROM entries ORDER BY updated_at DESC",
        )?;

        let entries = stmt
            .query_map([], |row| {
                Ok(Entry {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    username: row.get(2)?,
                    url: row.get(3)?,
                    notes: row.get(4)?,
                    category_id: row.get(5)?,
                    favorite: row.get(6).map(|v: i32| v != 0)?,
                    updated_at: parse_datetime(row.get(7)?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(entries)
    }

    #[allow(dead_code)]
    pub fn get_entry(&self, id: u32) -> Result<Entry, VaultError> {
        self.conn
            .query_row(
                "SELECT id, title, username, url, notes, category_id, favorite, updated_at
                 FROM entries WHERE id = ?1",
                [id],
                |row| {
                    Ok(Entry {
                        id: row.get(0)?,
                        title: row.get(1)?,
                        username: row.get(2)?,
                        url: row.get(3)?,
                        notes: row.get(4)?,
                        category_id: row.get(5)?,
                        favorite: row.get(6).map(|v: i32| v != 0)?,
                        updated_at: parse_datetime(row.get(7)?),
                    })
                },
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => VaultError::NotFound(id),
                other => VaultError::Db(other),
            })
    }

    pub fn save_entry(&self, entry: &Entry, encrypted_password: &[u8]) -> Result<u32, VaultError> {
        if entry.id == 0 {
            // Insert
            self.conn.execute(
                "INSERT INTO entries (title, username, url, password, notes, category_id, favorite, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                rusqlite::params![
                    entry.title,
                    entry.username,
                    entry.url,
                    encrypted_password,
                    entry.notes,
                    entry.category_id,
                    entry.favorite as i32,
                    entry.updated_at.to_rfc3339(),
                ],
            )?;
            Ok(self.conn.last_insert_rowid() as u32)
        } else {
            // Update
            self.conn.execute(
                "UPDATE entries SET title=?1, username=?2, url=?3, password=?4, notes=?5,
                 category_id=?6, favorite=?7, updated_at=?8 WHERE id=?9",
                rusqlite::params![
                    entry.title,
                    entry.username,
                    entry.url,
                    encrypted_password,
                    entry.notes,
                    entry.category_id,
                    entry.favorite as i32,
                    entry.updated_at.to_rfc3339(),
                    entry.id,
                ],
            )?;
            Ok(entry.id)
        }
    }

    pub fn delete_entry(&self, id: u32) -> Result<(), VaultError> {
        let affected = self.conn.execute("DELETE FROM entries WHERE id = ?1", [id])?;
        if affected == 0 {
            return Err(VaultError::NotFound(id));
        }
        Ok(())
    }

    pub fn get_encrypted_password(&self, id: u32) -> Result<Vec<u8>, VaultError> {
        self.conn
            .query_row(
                "SELECT password FROM entries WHERE id = ?1",
                [id],
                |row| row.get(0),
            )
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => VaultError::NotFound(id),
                other => VaultError::Db(other),
            })
    }

    #[allow(dead_code)]
    pub fn all_categories(&self) -> Result<Vec<Category>, VaultError> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, icon FROM categories ORDER BY name")?;

        let cats = stmt
            .query_map([], |row| {
                Ok(Category {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    icon: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(cats)
    }
}
