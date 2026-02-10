---
name: rust-systems-engineering
description: |
  Comprehensive Rust systems programming patterns for production backends.
  Triggers: rust error handling, async tokio, concurrency arc mutex, rusqlite database,
  serde serialization, FFI C bindings, rust testing, memory ownership borrowing,
  websocket tokio-tungstenite, rust cryptography, rust performance optimization,
  rust CLI clap tracing, rust build optimization LTO, rust systems programming
---

# Rust Systems Engineering

Production-tested patterns for Rust systems programming. Focused on systems-level
concerns — not web frameworks. Derived from patterns proven in large-scale Rust
applications including Fincept Terminal.

---

## Error Handling

### Custom Error Types with thiserror

```rust
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection pool error: {0}")]
    Pool(#[from] r2d2::Error),

    #[error("channel send error")]
    ChannelSend,

    #[error("resource not found: {resource} with id {id}")]
    NotFound { resource: String, id: String },

    #[error("operation timed out after {elapsed_ms}ms")]
    Timeout { elapsed_ms: u64 },

    #[error("configuration error: {0}")]
    Config(String),
}

// Implement conversion for types that don't support #[from]
impl<T> From<tokio::sync::mpsc::error::SendError<T>> for AppError {
    fn from(_: tokio::sync::mpsc::error::SendError<T>) -> Self {
        AppError::ChannelSend
    }
}
```

### The ? Operator and Error Propagation

```rust
use anyhow::{Context, Result};

// Use anyhow::Result for application-level functions
pub fn load_config(path: &str) -> Result<AppConfig> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config from {path}"))?;

    let config: AppConfig = serde_json::from_str(&content)
        .context("failed to parse config JSON")?;

    config.validate()
        .context("config validation failed")?;

    Ok(config)
}

// Use custom error types for library-level functions
pub fn get_record(pool: &DbPool, id: &str) -> Result<Record, AppError> {
    let conn = pool.get()?;  // r2d2::Error -> AppError::Pool via #[from]
    let record = conn.query_row(
        "SELECT * FROM records WHERE id = ?1",
        [id],
        |row| Record::try_from(row),
    )?;  // rusqlite::Error -> AppError::Database via #[from]
    Ok(record)
}
```

### Error Conversion for Tauri Commands

```rust
// Bridge between thiserror and serializable errors for IPC boundaries
impl From<AppError> for String {
    fn from(err: AppError) -> String {
        format!("{err:#}")
    }
}

// Or use serde for structured errors
#[derive(serde::Serialize)]
pub struct CommandError {
    pub code: String,
    pub message: String,
}

impl From<AppError> for CommandError {
    fn from(err: AppError) -> Self {
        let code = match &err {
            AppError::NotFound { .. } => "NOT_FOUND",
            AppError::Database(_) => "DATABASE_ERROR",
            AppError::Timeout { .. } => "TIMEOUT",
            _ => "INTERNAL_ERROR",
        };
        CommandError {
            code: code.to_string(),
            message: format!("{err}"),
        }
    }
}
```

---

## Async Patterns with Tokio

### Runtime Configuration

```rust
// Main entry point — configure the runtime explicitly
#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    // For CPU-bound work, use a separate blocking pool
    let result = tokio::task::spawn_blocking(|| {
        heavy_computation()
    }).await?;

    Ok(())
}

// For libraries, don't assume a runtime — accept a handle
pub struct Service {
    handle: tokio::runtime::Handle,
}
```

### Structured Concurrency with JoinSet

```rust
use tokio::task::JoinSet;

async fn process_batch(items: Vec<WorkItem>) -> Vec<Result<Output, AppError>> {
    let mut set = JoinSet::new();

    for item in items {
        set.spawn(async move {
            process_item(item).await
        });
    }

    let mut results = Vec::new();
    while let Some(res) = set.join_next().await {
        match res {
            Ok(output) => results.push(output),
            Err(join_err) => {
                tracing::error!("task panicked: {join_err}");
            }
        }
    }
    results
}
```

### select! for Multiple Futures

```rust
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};

async fn event_loop(
    mut cmd_rx: mpsc::Receiver<Command>,
    mut shutdown: tokio::sync::broadcast::Receiver<()>,
) {
    let mut heartbeat = interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            // Bias ensures commands are processed before heartbeats
            biased;

            Some(cmd) = cmd_rx.recv() => {
                handle_command(cmd).await;
            }

            _ = heartbeat.tick() => {
                send_heartbeat().await;
            }

            _ = shutdown.recv() => {
                tracing::info!("shutting down event loop");
                break;
            }
        }
    }
}
```

### Channel Patterns

```rust
use tokio::sync::{mpsc, oneshot, broadcast};

// Request-response via oneshot
struct Query {
    sql: String,
    reply: oneshot::Sender<Result<Vec<Row>, AppError>>,
}

async fn db_worker(mut rx: mpsc::Receiver<Query>, pool: DbPool) {
    while let Some(query) = rx.recv().await {
        let pool = pool.clone();
        let result = tokio::task::spawn_blocking(move || {
            let conn = pool.get()?;
            execute_query(&conn, &query.sql)
        }).await.unwrap();
        let _ = query.reply.send(result);
    }
}

// Broadcast for fan-out (e.g., WebSocket broadcasts)
fn create_event_bus() -> (broadcast::Sender<Event>, broadcast::Receiver<Event>) {
    broadcast::channel(1024)
}

// Bounded mpsc for backpressure
fn create_work_queue() -> (mpsc::Sender<WorkItem>, mpsc::Receiver<WorkItem>) {
    mpsc::channel(256)  // buffer size controls backpressure
}
```

---

## Concurrency Primitives

### Arc + Mutex for Shared Mutable State

```rust
use std::sync::{Arc, Mutex, RwLock};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub struct AppState {
    // RwLock: many readers, exclusive writers
    pub config: RwLock<AppConfig>,

    // Mutex: exclusive access, shorter critical sections
    pub connections: Mutex<Vec<ConnectionHandle>>,

    // Atomics: lock-free for counters and flags
    pub is_running: AtomicBool,
    pub request_count: AtomicU64,

    // DashMap: concurrent HashMap, no external locking needed
    pub sessions: dashmap::DashMap<String, SessionData>,
}

impl AppState {
    pub fn increment_requests(&self) -> u64 {
        self.request_count.fetch_add(1, Ordering::Relaxed)
    }

    pub fn update_config(&self, new_config: AppConfig) {
        let mut config = self.config.write().unwrap();
        *config = new_config;
    }

    pub fn get_session(&self, id: &str) -> Option<SessionData> {
        self.sessions.get(id).map(|entry| entry.value().clone())
    }
}

// Wrap in Arc for sharing across threads/tasks
type SharedState = Arc<AppState>;
```

### DashMap Patterns

```rust
use dashmap::DashMap;

pub struct ConnectionRegistry {
    connections: DashMap<String, ConnectionInfo>,
}

impl ConnectionRegistry {
    pub fn register(&self, id: String, info: ConnectionInfo) {
        self.connections.insert(id, info);
    }

    pub fn remove(&self, id: &str) -> Option<ConnectionInfo> {
        self.connections.remove(id).map(|(_, v)| v)
    }

    // Iterate without holding a global lock
    pub fn active_count(&self) -> usize {
        self.connections.iter()
            .filter(|entry| entry.value().is_active)
            .count()
    }

    // entry API for atomic read-modify-write
    pub fn increment_messages(&self, id: &str) {
        if let Some(mut entry) = self.connections.get_mut(id) {
            entry.message_count += 1;
        }
    }
}
```

### Lock-Free Patterns

```rust
use std::sync::atomic::{AtomicU64, Ordering};

pub struct RateLimiter {
    tokens: AtomicU64,
    max_tokens: u64,
    last_refill: AtomicU64,
}

impl RateLimiter {
    pub fn try_acquire(&self) -> bool {
        loop {
            let current = self.tokens.load(Ordering::Acquire);
            if current == 0 {
                return false;
            }
            // Compare-and-swap for lock-free decrement
            match self.tokens.compare_exchange_weak(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(_) => continue,  // retry on contention
            }
        }
    }
}
```

---

## Database Patterns (rusqlite + r2d2)

### Connection Pool with WAL Mode

```rust
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;

pub type DbPool = Pool<SqliteConnectionManager>;

pub fn create_pool(db_path: &str) -> Result<DbPool, AppError> {
    let manager = SqliteConnectionManager::file(db_path)
        .with_init(|conn| {
            // WAL mode for concurrent reads during writes
            conn.execute_batch("
                PRAGMA journal_mode = WAL;
                PRAGMA synchronous = NORMAL;
                PRAGMA foreign_keys = ON;
                PRAGMA busy_timeout = 5000;
                PRAGMA cache_size = -20000;  -- 20MB
                PRAGMA mmap_size = 268435456;  -- 256MB
            ")?;
            Ok(())
        });

    let pool = Pool::builder()
        .max_size(8)
        .min_idle(Some(2))
        .connection_timeout(std::time::Duration::from_secs(10))
        .build(manager)?;

    Ok(pool)
}
```

### Prepared Statements and Transactions

```rust
pub fn insert_records(pool: &DbPool, records: &[Record]) -> Result<usize, AppError> {
    let mut conn = pool.get()?;
    let tx = conn.transaction()?;

    let mut count = 0;
    {
        let mut stmt = tx.prepare_cached(
            "INSERT OR REPLACE INTO records (id, name, data, updated_at)
             VALUES (?1, ?2, ?3, ?4)"
        )?;

        for record in records {
            stmt.execute(rusqlite::params![
                record.id,
                record.name,
                serde_json::to_string(&record.data)?,
                record.updated_at.timestamp(),
            ])?;
            count += 1;
        }
    }

    tx.commit()?;
    Ok(count)
}

pub fn query_with_pagination(
    pool: &DbPool,
    filter: &str,
    offset: i64,
    limit: i64,
) -> Result<Vec<Record>, AppError> {
    let conn = pool.get()?;
    let mut stmt = conn.prepare_cached(
        "SELECT id, name, data, updated_at FROM records
         WHERE name LIKE ?1
         ORDER BY updated_at DESC
         LIMIT ?2 OFFSET ?3"
    )?;

    let rows = stmt.query_map(
        rusqlite::params![format!("%{filter}%"), limit, offset],
        |row| {
            Ok(Record {
                id: row.get(0)?,
                name: row.get(1)?,
                data: serde_json::from_str(&row.get::<_, String>(2)?).unwrap_or_default(),
                updated_at: row.get(3)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>().map_err(AppError::from)
}
```

### Schema Migrations

```rust
const MIGRATIONS: &[&str] = &[
    // v1: initial schema
    "CREATE TABLE IF NOT EXISTS records (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        data TEXT NOT NULL DEFAULT '{}',
        updated_at INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_records_updated ON records(updated_at);",

    // v2: add categories
    "ALTER TABLE records ADD COLUMN category TEXT DEFAULT 'general';
     CREATE INDEX IF NOT EXISTS idx_records_category ON records(category);",

    // v3: add full-text search
    "CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(name, data, content=records);",
];

pub fn run_migrations(conn: &Connection) -> Result<(), AppError> {
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)",
        [],
    )?;

    let current: i64 = conn
        .query_row("SELECT COALESCE(MAX(version), 0) FROM schema_version", [], |r| r.get(0))
        .unwrap_or(0);

    for (i, migration) in MIGRATIONS.iter().enumerate() {
        let version = (i + 1) as i64;
        if version > current {
            tracing::info!("applying migration v{version}");
            conn.execute_batch(migration)?;
            conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [version])?;
        }
    }

    Ok(())
}
```

---

## Serialization with serde

### Custom Serialize/Deserialize

```rust
use serde::{Deserialize, Serialize, Deserializer, Serializer};
use serde::de::{self, Visitor};

#[derive(Debug, Clone)]
pub struct Timestamp(pub i64);

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(self.0)
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TimestampVisitor;
        impl<'de> Visitor<'de> for TimestampVisitor {
            type Value = Timestamp;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "an integer or ISO 8601 string")
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Timestamp, E> {
                Ok(Timestamp(v))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Timestamp, E> {
                chrono::DateTime::parse_from_rfc3339(v)
                    .map(|dt| Timestamp(dt.timestamp()))
                    .map_err(de::Error::custom)
            }
        }
        deserializer.deserialize_any(TimestampVisitor)
    }
}

// Flattening and renaming for API compatibility
#[derive(Serialize, Deserialize)]
pub struct ApiResponse<T: Serialize> {
    #[serde(rename = "statusCode")]
    pub status_code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub data: T,
}
```

### Zero-Copy Deserialization

```rust
use serde::Deserialize;

// Borrows from the input string — no allocation for string fields
#[derive(Deserialize)]
pub struct LogEntry<'a> {
    pub timestamp: i64,
    pub level: &'a str,
    pub message: &'a str,
    #[serde(borrow)]
    pub fields: std::collections::HashMap<&'a str, &'a str>,
}

pub fn parse_log_batch(input: &str) -> Result<Vec<LogEntry<'_>>, serde_json::Error> {
    // The returned LogEntry values borrow directly from `input`
    serde_json::from_str(input)
}
```

---

## FFI Patterns

### Calling C Libraries

```rust
// build.rs
fn main() {
    // Link a system library
    println!("cargo:rustc-link-lib=dylib=sodium");
    println!("cargo:rustc-link-search=native=/usr/local/lib");

    // Or build C code with cc crate
    cc::Build::new()
        .file("src/native/helper.c")
        .flag("-O2")
        .compile("helper");
}
```

```rust
// src/ffi.rs
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

extern "C" {
    fn native_process(input: *const c_char, len: c_int) -> *mut c_char;
    fn native_free(ptr: *mut c_char);
}

pub fn process_native(input: &str) -> Result<String, AppError> {
    let c_input = CString::new(input)
        .map_err(|_| AppError::Config("input contains null byte".into()))?;

    unsafe {
        let result_ptr = native_process(c_input.as_ptr(), input.len() as c_int);
        if result_ptr.is_null() {
            return Err(AppError::Config("native processing failed".into()));
        }
        let result = CStr::from_ptr(result_ptr)
            .to_string_lossy()
            .into_owned();
        native_free(result_ptr);
        Ok(result)
    }
}
```

### Exposing Rust as a C Library (cdylib)

```rust
// Cargo.toml: [lib] crate-type = ["cdylib"]

#[no_mangle]
pub extern "C" fn rust_process(input: *const u8, len: usize) -> *mut u8 {
    let slice = unsafe { std::slice::from_raw_parts(input, len) };
    let input_str = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let result = process(input_str);
    let c_string = match CString::new(result) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    c_string.into_raw() as *mut u8
}

#[no_mangle]
pub extern "C" fn rust_free(ptr: *mut u8) {
    if !ptr.is_null() {
        unsafe { drop(CString::from_raw(ptr as *mut c_char)); }
    }
}
```

---

## WebSocket Patterns (tokio-tungstenite)

### Connection Management with Heartbeat

```rust
use tokio_tungstenite::{connect_async, tungstenite::Message};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use std::time::Duration;

pub struct WsClient {
    tx: mpsc::Sender<Message>,
    is_connected: Arc<AtomicBool>,
}

impl WsClient {
    pub async fn connect(
        url: &str,
        event_tx: mpsc::Sender<Event>,
    ) -> Result<Self, AppError> {
        let (ws_stream, _) = connect_async(url).await
            .map_err(|e| AppError::Config(format!("websocket connect failed: {e}")))?;

        let (mut write, mut read) = ws_stream.split();
        let (msg_tx, mut msg_rx) = mpsc::channel::<Message>(256);
        let is_connected = Arc::new(AtomicBool::new(true));
        let connected = is_connected.clone();

        // Writer task
        tokio::spawn(async move {
            while let Some(msg) = msg_rx.recv().await {
                if write.send(msg).await.is_err() {
                    break;
                }
            }
        });

        // Reader task with heartbeat
        let ping_tx = msg_tx.clone();
        tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
            let mut missed_pongs = 0u32;

            loop {
                tokio::select! {
                    msg = read.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                let _ = event_tx.send(Event::Message(text)).await;
                            }
                            Some(Ok(Message::Pong(_))) => {
                                missed_pongs = 0;
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                connected.store(false, Ordering::Release);
                                let _ = event_tx.send(Event::Disconnected).await;
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ = heartbeat.tick() => {
                        missed_pongs += 1;
                        if missed_pongs > 3 {
                            tracing::warn!("missed 3 pongs, disconnecting");
                            connected.store(false, Ordering::Release);
                            break;
                        }
                        let _ = ping_tx.send(Message::Ping(vec![].into())).await;
                    }
                }
            }
        });

        Ok(Self { tx: msg_tx, is_connected })
    }

    pub async fn send(&self, text: String) -> Result<(), AppError> {
        self.tx.send(Message::Text(text.into())).await.map_err(|_| AppError::ChannelSend)
    }
}
```

### Reconnection with Exponential Backoff

```rust
pub async fn connect_with_retry(
    url: &str,
    event_tx: mpsc::Sender<Event>,
    max_retries: u32,
) -> Result<WsClient, AppError> {
    let mut attempt = 0;
    loop {
        match WsClient::connect(url, event_tx.clone()).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                attempt += 1;
                if attempt >= max_retries {
                    return Err(e);
                }
                let delay = Duration::from_millis(
                    (2u64.pow(attempt) * 100).min(30_000)
                );
                tracing::warn!("reconnect attempt {attempt}/{max_retries} in {delay:?}");
                tokio::time::sleep(delay).await;
            }
        }
    }
}
```

---

## Cryptography

### Credential Encryption with AES-GCM

```rust
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit, OsRng};
use sha2::Sha256;
use hmac::Hmac;
use pbkdf2::pbkdf2_hmac;

pub fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 600_000, &mut key);
    key
}

pub fn encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| AppError::Config(format!("encryption failed: {e}")))?;

    // Prepend nonce to ciphertext for storage
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, AppError> {
    if data.len() < 12 {
        return Err(AppError::Config("ciphertext too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| AppError::Config(format!("decryption failed: {e}")))
}
```

---

## Performance

### Collection Selection

```rust
use std::collections::{BTreeMap, HashMap, VecDeque};

// BTreeMap: ordered iteration, range queries, O(log n) ops
// Use when you need sorted keys or range scans
let mut ordered: BTreeMap<String, Value> = BTreeMap::new();
for (k, v) in ordered.range("2024-01".."2024-12") { /* date range scan */ }

// HashMap with ahash: fastest for point lookups on hot paths
use ahash::AHashMap;
let mut fast_map: AHashMap<u64, Data> = AHashMap::with_capacity(10_000);

// hashbrown::HashMap: same as std HashMap but exposes raw API
use hashbrown::HashMap as RawMap;

// VecDeque: O(1) push/pop at both ends — ring buffer for recent items
let mut recent: VecDeque<LogEntry> = VecDeque::with_capacity(1000);
if recent.len() >= 1000 {
    recent.pop_front();  // evict oldest
}
recent.push_back(entry);

// SmallVec: stack-allocated for small collections, heap for larger
use smallvec::SmallVec;
let mut tags: SmallVec<[String; 4]> = SmallVec::new();  // inline up to 4
```

### Avoiding Allocations in Hot Paths

```rust
// Pre-allocate and reuse buffers
pub struct Processor {
    buffer: Vec<u8>,
    scratch: String,
}

impl Processor {
    pub fn process(&mut self, input: &[u8]) -> &str {
        self.buffer.clear();
        self.buffer.extend_from_slice(input);

        self.scratch.clear();
        // reuses existing allocation
        self.scratch.push_str(std::str::from_utf8(&self.buffer).unwrap_or(""));
        &self.scratch
    }
}

// Use Cow<str> to avoid cloning when not needed
use std::borrow::Cow;

fn normalize(input: &str) -> Cow<'_, str> {
    if input.contains('\t') {
        Cow::Owned(input.replace('\t', "    "))
    } else {
        Cow::Borrowed(input)  // zero-copy when no modification needed
    }
}
```

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encryption_roundtrip() {
        let key = derive_key("test-password", b"test-salt");
        let plaintext = b"sensitive data";

        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_channel_communication() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        tx.send("hello".to_string()).await.unwrap();
        assert_eq!(rx.recv().await.unwrap(), "hello");
    }

    // Test error variants
    #[test]
    fn test_error_display() {
        let err = AppError::NotFound {
            resource: "user".into(),
            id: "123".into(),
        };
        assert_eq!(err.to_string(), "resource not found: user with id 123");
    }
}
```

### Property-Based Testing with proptest

```rust
#[cfg(test)]
mod proptests {
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn encryption_roundtrip_any_data(data in prop::collection::vec(any::<u8>(), 0..1024)) {
            let key = [0u8; 32];  // fixed key for testing
            let encrypted = encrypt(&data, &key).unwrap();
            let decrypted = decrypt(&encrypted, &key).unwrap();
            prop_assert_eq!(decrypted, data);
        }

        #[test]
        fn rate_limiter_never_goes_negative(ops in 1..1000u32) {
            let limiter = RateLimiter::new(100);
            for _ in 0..ops {
                limiter.try_acquire();
            }
            assert!(limiter.tokens.load(Ordering::Relaxed) <= 100);
        }
    }
}
```

### Benchmarking with criterion

```rust
// benches/collections.rs
use criterion::{criterion_group, criterion_main, Criterion, black_box};

fn bench_map_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("map_lookup");

    let std_map: HashMap<u64, u64> = (0..10_000).map(|i| (i, i * 2)).collect();
    let ahash_map: AHashMap<u64, u64> = (0..10_000).map(|i| (i, i * 2)).collect();

    group.bench_function("std_hashmap", |b| {
        b.iter(|| std_map.get(black_box(&5000)))
    });

    group.bench_function("ahash_map", |b| {
        b.iter(|| ahash_map.get(black_box(&5000)))
    });

    group.finish();
}

criterion_group!(benches, bench_map_lookup);
criterion_main!(benches);
```

---

## CLI Patterns

### Argument Parsing with clap

```rust
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(name = "myapp", version, about = "Production system CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    pub config: String,

    /// Logging verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the server
    Serve {
        #[arg(short, long, default_value = "8080")]
        port: u16,
    },
    /// Run database migrations
    Migrate {
        #[arg(value_enum)]
        direction: MigrateDirection,
    },
}

#[derive(ValueEnum, Clone)]
pub enum MigrateDirection {
    Up,
    Down,
}
```

### Structured Logging with tracing

```rust
use tracing::{info, warn, error, instrument, Level};
use tracing_subscriber::{fmt, EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

pub fn init_tracing(verbosity: u8) {
    let filter = match verbosity {
        0 => "warn,myapp=info",
        1 => "info,myapp=debug",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with(fmt::layer()
            .with_target(true)
            .with_thread_ids(true)
            .with_file(true)
            .with_line_number(true))
        .init();
}

// Instrument functions for automatic span creation
#[instrument(skip(pool), fields(record_count))]
pub fn process_batch(pool: &DbPool, batch_id: &str) -> Result<(), AppError> {
    let records = fetch_records(pool, batch_id)?;
    tracing::Span::current().record("record_count", records.len());

    for record in &records {
        info!(record_id = %record.id, "processing record");
    }

    Ok(())
}
```

---

## Build Optimization

### Release Profile Configuration

```toml
# Cargo.toml

[profile.release]
opt-level = 3
lto = "fat"           # Full link-time optimization — slower build, faster binary
codegen-units = 1      # Single codegen unit — better optimization
panic = "abort"        # No unwinding — smaller binary
strip = "symbols"      # Strip debug symbols from release binary

[profile.release-debug]
inherits = "release"
strip = false
debug = true           # Release optimizations with debug symbols for profiling

[profile.dev]
opt-level = 0
debug = true

[profile.dev.package."*"]
opt-level = 2          # Optimize dependencies even in dev for faster runtime
```

### Cross-Compilation

```toml
# .cargo/config.toml

[target.x86_64-unknown-linux-gnu]
linker = "x86_64-linux-gnu-gcc"

[target.x86_64-pc-windows-msvc]
rustflags = ["-C", "target-feature=+crt-static"]
```

---

## Memory Management Patterns

### Lifetime Annotations

```rust
// Parser that borrows from input — no allocation
pub struct Parser<'input> {
    source: &'input str,
    position: usize,
}

impl<'input> Parser<'input> {
    pub fn new(source: &'input str) -> Self {
        Self { source, position: 0 }
    }

    pub fn next_token(&mut self) -> Option<&'input str> {
        let remaining = &self.source[self.position..];
        let end = remaining.find(char::is_whitespace).unwrap_or(remaining.len());
        if end == 0 {
            return None;
        }
        let token = &remaining[..end];
        self.position += end;
        self.position += remaining[end..].find(|c: char| !c.is_whitespace()).unwrap_or(0);
        Some(token)
    }
}

// Self-referential struct pattern using Pin
use std::pin::Pin;

pub struct OwnedParser {
    data: String,
    // SAFETY: parser borrows from data, which is pinned
    parser: Option<Parser<'static>>,
}
```

### Arena Allocation for Graph Structures

```rust
use typed_arena::Arena;

pub struct Graph<'arena> {
    arena: &'arena Arena<Node>,
}

pub struct Node {
    pub id: u64,
    pub children: Vec<*const Node>,
}

impl<'arena> Graph<'arena> {
    pub fn add_node(&self, id: u64) -> &Node {
        self.arena.alloc(Node {
            id,
            children: Vec::new(),
        })
    }
}
```
