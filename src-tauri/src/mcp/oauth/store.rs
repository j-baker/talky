//! Persistent storage for OAuth clients, authorization codes, and tokens.
//!
//! Backed by a dedicated sqlite db (`mcp_oauth.db`) in the app data dir so
//! that wiping it doesn't disturb sessions/history.

use anyhow::Result;
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use rusqlite_migration::{Migrations, M};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{AppHandle, Manager};

static MIGRATIONS: &[M] = &[
    M::up(
        "CREATE TABLE IF NOT EXISTS signing_key (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            key BLOB NOT NULL,
            created_at INTEGER NOT NULL
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_used_at INTEGER,
            revoked INTEGER NOT NULL DEFAULT 0
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            scope TEXT,
            created_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS refresh_tokens (
            jti TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );",
    ),
    M::up(
        "CREATE TABLE IF NOT EXISTS revoked_access_jti (
            jti TEXT PRIMARY KEY,
            revoked_at INTEGER NOT NULL
        );",
    ),
];

pub struct OAuthStore {
    db_path: PathBuf,
    /// Single in-process mutex around the db path to keep writes serial.
    /// Reads still open their own connection (sqlite handles concurrency).
    write_lock: Mutex<()>,
}

#[derive(Debug, Clone)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AuthCodeRecord {
    #[allow(dead_code)]
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    #[allow(dead_code)]
    pub scope: Option<String>,
    pub created_at: i64,
    pub used: bool,
}

impl OAuthStore {
    pub fn open(app: &AppHandle) -> Result<Self> {
        let dir = app.path().app_data_dir()?;
        if !dir.exists() {
            std::fs::create_dir_all(&dir)?;
        }
        let db_path = dir.join("mcp_oauth.db");

        let mut conn = Connection::open(&db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        let migrations = Migrations::new(MIGRATIONS.to_vec());
        #[cfg(debug_assertions)]
        migrations
            .validate()
            .expect("Invalid mcp_oauth migrations");
        migrations.to_latest(&mut conn)?;

        Ok(Self {
            db_path,
            write_lock: Mutex::new(()),
        })
    }

    fn conn(&self) -> Result<Connection> {
        Ok(Connection::open(&self.db_path)?)
    }

    pub fn get_or_create_signing_key(&self) -> Result<Vec<u8>> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let conn = self.conn()?;
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT key FROM signing_key WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(k) = existing {
            return Ok(k);
        }
        // First time: generate 32 bytes of randomness for HS256.
        use rand::RngCore;
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        conn.execute(
            "INSERT INTO signing_key (id, key, created_at) VALUES (1, ?1, ?2)",
            params![key, Utc::now().timestamp()],
        )?;
        Ok(key)
    }

    pub fn register_client(
        &self,
        name: &str,
        redirect_uris: &[String],
    ) -> Result<ClientRecord> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let uris_json = serde_json::to_string(redirect_uris)?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO clients (id, name, redirect_uris, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id, name, uris_json, now],
        )?;
        Ok(ClientRecord {
            id,
            name: name.to_string(),
            redirect_uris: redirect_uris.to_vec(),
            created_at: now,
            last_used_at: None,
        })
    }

    pub fn get_client(&self, client_id: &str) -> Result<Option<ClientRecord>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT id, name, redirect_uris, created_at, last_used_at FROM clients
                 WHERE id = ?1 AND revoked = 0",
                params![client_id],
                |r| {
                    let uris_json: String = r.get(2)?;
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, String>(1)?,
                        uris_json,
                        r.get::<_, i64>(3)?,
                        r.get::<_, Option<i64>>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, name, uris_json, created_at, last_used_at)) = row else {
            return Ok(None);
        };
        let redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
        Ok(Some(ClientRecord {
            id,
            name,
            redirect_uris,
            created_at,
            last_used_at,
        }))
    }

    pub fn list_clients(&self) -> Result<Vec<ClientRecord>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, name, redirect_uris, created_at, last_used_at FROM clients
             WHERE revoked = 0 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let uris_json: String = r.get(2)?;
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                uris_json,
                r.get::<_, i64>(3)?,
                r.get::<_, Option<i64>>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, name, uris_json, created_at, last_used_at) = row?;
            let redirect_uris: Vec<String> = serde_json::from_str(&uris_json).unwrap_or_default();
            out.push(ClientRecord {
                id,
                name,
                redirect_uris,
                created_at,
                last_used_at,
            });
        }
        Ok(out)
    }

    pub fn touch_client(&self, client_id: &str) -> Result<()> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let conn = self.conn()?;
        conn.execute(
            "UPDATE clients SET last_used_at = ?1 WHERE id = ?2",
            params![Utc::now().timestamp(), client_id],
        )?;
        Ok(())
    }

    /// Mark the client as revoked; also wipe its outstanding refresh tokens.
    pub fn revoke_client(&self, client_id: &str) -> Result<()> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE clients SET revoked = 1 WHERE id = ?1",
            params![client_id],
        )?;
        tx.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE client_id = ?1",
            params![client_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn store_auth_code(
        &self,
        code: &str,
        client_id: &str,
        redirect_uri: &str,
        code_challenge: &str,
        scope: Option<&str>,
    ) -> Result<()> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO auth_codes (code, client_id, redirect_uri, code_challenge, scope, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![code, client_id, redirect_uri, code_challenge, scope, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// Atomically consume an auth code. Returns Ok(Some(record)) on first use,
    /// Ok(None) if missing/expired/already used.
    pub fn consume_auth_code(&self, code: &str) -> Result<Option<AuthCodeRecord>> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp();
        const TTL_SECS: i64 = 10 * 60;
        let record: Option<AuthCodeRecord> = tx
            .query_row(
                "SELECT code, client_id, redirect_uri, code_challenge, scope, created_at, used
                 FROM auth_codes WHERE code = ?1",
                params![code],
                |r| {
                    Ok(AuthCodeRecord {
                        code: r.get(0)?,
                        client_id: r.get(1)?,
                        redirect_uri: r.get(2)?,
                        code_challenge: r.get(3)?,
                        scope: r.get(4)?,
                        created_at: r.get(5)?,
                        used: r.get::<_, i64>(6)? != 0,
                    })
                },
            )
            .optional()?;
        let Some(record) = record else {
            tx.commit()?;
            return Ok(None);
        };
        if record.used || now - record.created_at > TTL_SECS {
            tx.execute("DELETE FROM auth_codes WHERE code = ?1", params![code])?;
            tx.commit()?;
            return Ok(None);
        }
        tx.execute("UPDATE auth_codes SET used = 1 WHERE code = ?1", params![code])?;
        tx.commit()?;
        Ok(Some(record))
    }

    pub fn store_refresh(&self, jti: &str, client_id: &str, expires_at: i64) -> Result<()> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO refresh_tokens (jti, client_id, expires_at) VALUES (?1, ?2, ?3)",
            params![jti, client_id, expires_at],
        )?;
        Ok(())
    }

    /// Atomically rotate a refresh token. Returns the client_id on success.
    pub fn consume_refresh(&self, jti: &str) -> Result<Option<String>> {
        let _g = self
            .write_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("oauth store write lock poisoned"))?;
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let now = Utc::now().timestamp();
        let row: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT client_id, expires_at, revoked FROM refresh_tokens WHERE jti = ?1",
                params![jti],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((client_id, expires_at, revoked)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        if revoked != 0 || expires_at < now {
            tx.execute("DELETE FROM refresh_tokens WHERE jti = ?1", params![jti])?;
            tx.commit()?;
            return Ok(None);
        }
        // Single-use: delete on consume.
        tx.execute("DELETE FROM refresh_tokens WHERE jti = ?1", params![jti])?;
        tx.commit()?;
        Ok(Some(client_id))
    }

    pub fn is_access_jti_revoked(&self, jti: &str) -> Result<bool> {
        let conn = self.conn()?;
        let exists: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM revoked_access_jti WHERE jti = ?1",
                params![jti],
                |r| r.get(0),
            )
            .optional()?;
        Ok(exists.is_some())
    }
}
