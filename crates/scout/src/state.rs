use anyhow::{Context, Result, ensure};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use sentinel_protocol::{Observation, QueueHealth};
use serde::Serialize;
use sqlx::{
    Connection, Row, SqliteConnection, SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};
use std::{
    fs::{File, OpenOptions},
    path::Path,
    time::Duration,
};
use uuid::Uuid;

pub const MAX_QUEUE_EVENTS: i64 = 1000;
pub const MAX_QUEUE_BYTES: i64 = 128 * 1024 * 1024;
#[derive(Serialize)]
pub struct PublicStatus {
    pub installation_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub public_key: String,
    pub queue: QueueHealth,
}

/// Read existing state without initializing it or acquiring the Scout writer lock.
pub async fn read_status(path: &Path) -> Result<PublicStatus> {
    let directory = std::fs::symlink_metadata(path)
        .context("Scout state directory is unavailable; initialize with scout init first")?;
    ensure!(
        directory.is_dir(),
        "state directory must be a real directory"
    );
    let db = path.join("state.sqlite3");
    let metadata = std::fs::symlink_metadata(&db)
        .context("Scout state database is unavailable; initialize with scout init first")?;
    ensure!(metadata.is_file(), "state database must be a regular file");
    // Preserve WAL visibility while the writer is running: immutable mode would
    // incorrectly assume the database cannot change. Do not set writer pragmas.
    let options = SqliteConnectOptions::new()
        .filename(&db)
        .read_only(true)
        .create_if_missing(false)
        .pragma("query_only", "ON")
        .busy_timeout(Duration::from_secs(5));
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .context("open existing Scout state read-only")?;
    // One SELECT gives identity and queue health from the same committed snapshot.
    let rows = sqlx::query(
        r#"SELECT id, asset_id, signing_seed, overflow_count,
           (SELECT count(*) FROM pending_events WHERE NOT "delete") AS pending_events,
           (SELECT COALESCE(sum(length(payload)),0) FROM pending_events WHERE NOT "delete") AS pending_bytes
           FROM local_identity WHERE NOT "delete" LIMIT 2"#,
    )
    .fetch_all(&mut connection)
    .await;
    connection
        .close()
        .await
        .context("close Scout status reader")?;
    let rows = rows.context(
        "read existing Scout identity and queue; state is not initialized or is incompatible",
    )?;
    ensure!(
        rows.len() <= 1,
        "multiple local identities; manual recovery required"
    );
    let row = rows
        .into_iter()
        .next()
        .context("Scout identity is missing; initialize with scout init first")?;
    // Older state stores only the seed. Derive the public key locally without
    // migrating the database or including private material in the status DTO.
    let seed: [u8; 32] = row
        .try_get::<Vec<u8>, _>("signing_seed")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid stored signing key"))?;
    Ok(PublicStatus {
        installation_id: row.try_get::<String, _>("id")?.parse()?,
        asset_id: row
            .try_get::<Option<String>, _>("asset_id")?
            .map(|s| s.parse())
            .transpose()?,
        public_key: hex::encode(SigningKey::from_bytes(&seed).verifying_key().to_bytes()),
        queue: QueueHealth {
            pending_events: row.try_get("pending_events")?,
            pending_bytes: row.try_get("pending_bytes")?,
            overflow_count: row.try_get("overflow_count")?,
            max_events: MAX_QUEUE_EVENTS,
            max_bytes: MAX_QUEUE_BYTES,
        },
    })
}

pub struct Identity {
    pub installation_id: Uuid,
    pub asset_id: Option<Uuid>,
    pub key: SigningKey,
}
pub struct LocalState {
    pub pool: SqlitePool,
    pub identity: Identity,
    _lock: File,
}
impl LocalState {
    pub async fn open(path: &Path) -> Result<Self> {
        std::fs::create_dir_all(path).context("create Scout state directory")?;
        ensure!(
            !std::fs::symlink_metadata(path)?.file_type().is_symlink(),
            "state directory must not be a symbolic link"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
        let lock_path = path.join("active.lock");
        reject_symlink(&lock_path)?;
        let lock = private_file(&lock_path)?;
        FileExt::try_lock_exclusive(&lock)
            .context("Scout state is already owned by another process")?;
        let db = path.join("state.sqlite3");
        reject_symlink(&db)?;
        private_file(&db)?;
        let options = SqliteConnectOptions::new()
            .filename(&db)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5))
            .pragma("max_page_count", "40960")
            .pragma("journal_size_limit", "8388608")
            .pragma("wal_autocheckpoint", "512");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        sqlx::raw_sql(r#"
CREATE TABLE IF NOT EXISTS local_identity (
 id TEXT PRIMARY KEY NOT NULL, create_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 update_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), "delete" INTEGER NOT NULL DEFAULT 0 CHECK ("delete"=0),
 signing_seed BLOB NOT NULL CHECK (length(signing_seed)=32), asset_id TEXT, active_epoch INTEGER NOT NULL DEFAULT 0,
 collection_sequence INTEGER NOT NULL DEFAULT 0, metric_sequence INTEGER NOT NULL DEFAULT 0, overflow_count INTEGER NOT NULL DEFAULT 0
);
CREATE TRIGGER IF NOT EXISTS identity_freeze BEFORE UPDATE ON local_identity
WHEN NEW.id<>OLD.id OR NEW.create_time<>OLD.create_time
BEGIN SELECT RAISE(ABORT,'immutable identity metadata'); END;
CREATE TRIGGER IF NOT EXISTS identity_update AFTER UPDATE ON local_identity
WHEN NEW.update_time=OLD.update_time
BEGIN UPDATE local_identity SET update_time=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=NEW.id; END;
CREATE TABLE IF NOT EXISTS pending_events (
 id TEXT PRIMARY KEY NOT NULL, create_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
 update_time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), "delete" INTEGER NOT NULL DEFAULT 0 CHECK ("delete"=0),
 sequence INTEGER NOT NULL UNIQUE, subject TEXT NOT NULL, payload BLOB NOT NULL
);
CREATE TRIGGER IF NOT EXISTS pending_immutable BEFORE UPDATE ON pending_events
BEGIN SELECT RAISE(ABORT,'queued events are immutable'); END;
"#).execute(&pool).await?;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM local_identity")
            .fetch_one(&pool)
            .await?;
        ensure!(
            count <= 1,
            "multiple local identities; manual recovery required"
        );
        if count == 0 {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed)
                .map_err(|_| anyhow::anyhow!("secure randomness unavailable"))?;
            sqlx::query("INSERT INTO local_identity(id,signing_seed) VALUES($1,$2)")
                .bind(Uuid::new_v4().to_string())
                .bind(seed.to_vec())
                .execute(&pool)
                .await?;
        }
        let row =
            sqlx::query("SELECT id,asset_id,signing_seed FROM local_identity WHERE NOT \"delete\"")
                .fetch_one(&pool)
                .await?;
        let seed: [u8; 32] = row
            .try_get::<Vec<u8>, _>("signing_seed")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid stored signing key"))?;
        let identity = Identity {
            installation_id: row.try_get::<String, _>("id")?.parse()?,
            asset_id: row
                .try_get::<Option<String>, _>("asset_id")?
                .map(|s| s.parse())
                .transpose()?,
            key: SigningKey::from_bytes(&seed),
        };
        Ok(Self {
            pool,
            identity,
            _lock: lock,
        })
    }
    pub async fn bind(&mut self, asset: Uuid) -> Result<()> {
        ensure!(
            self.identity.asset_id.is_none_or(|id| id == asset),
            "asset binding changed; refusing to overwrite identity"
        );
        sqlx::query("UPDATE local_identity SET asset_id=$1")
            .bind(asset.to_string())
            .execute(&self.pool)
            .await?;
        self.identity.asset_id = Some(asset);
        Ok(())
    }
    pub async fn new_epoch(&self) -> Result<i64> {
        Ok(sqlx::query_scalar("UPDATE local_identity SET active_epoch=active_epoch+1 WHERE active_epoch<9223372036854775807 RETURNING active_epoch").fetch_one(&self.pool).await?)
    }
    pub async fn health(&self) -> Result<QueueHealth> {
        let row=sqlx::query("SELECT count(*) AS count,COALESCE(sum(length(payload)),0) AS bytes FROM pending_events").fetch_one(&self.pool).await?;
        Ok(QueueHealth {
            pending_events: row.get("count"),
            pending_bytes: row.get("bytes"),
            overflow_count: sqlx::query_scalar("SELECT overflow_count FROM local_identity")
                .fetch_one(&self.pool)
                .await?,
            max_events: MAX_QUEUE_EVENTS,
            max_bytes: MAX_QUEUE_BYTES,
        })
    }
    pub async fn enqueue(&self, mut e: Observation) -> Result<bool> {
        let health = self.health().await?;
        let mut tx = self.pool.begin().await?;
        let row=sqlx::query("UPDATE local_identity SET collection_sequence=collection_sequence+3,metric_sequence=metric_sequence+1 WHERE collection_sequence<9223372036854775801 AND metric_sequence<9223372036854775806 RETURNING collection_sequence,metric_sequence").fetch_one(&mut *tx).await?;
        e.collection_sequence = row.get::<i64, _>("collection_sequence") - 3;
        e.metric_sequence = row.get("metric_sequence");
        e.queue_health = health.clone();
        let bytes = crate::budget::sign_bounded(&mut e, &self.identity.key)?;
        if health.pending_events >= MAX_QUEUE_EVENTS
            || health.pending_bytes + bytes.len() as i64 > MAX_QUEUE_BYTES
        {
            sqlx::query("UPDATE local_identity SET overflow_count=overflow_count+1")
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            tracing::warn!(
                pending_events = health.pending_events,
                pending_bytes = health.pending_bytes,
                error_kind = "queue_full",
                "new observation skipped; pending events retained"
            );
            return Ok(false);
        }
        sqlx::query("INSERT INTO pending_events(id,sequence,subject,payload) VALUES($1,$2,$3,$4)")
            .bind(e.event_id.to_string())
            .bind(e.metric_sequence)
            .bind(e.subject())
            .bind(bytes)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(true)
    }
    pub async fn next(&self) -> Result<Option<(String, String, Vec<u8>)>> {
        Ok(sqlx::query_as(
            "SELECT id,subject,payload FROM pending_events ORDER BY sequence LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?)
    }
    pub async fn acknowledge(&self, event_id: &str) -> Result<()> {
        sqlx::query("DELETE FROM pending_events WHERE id=$1")
            .bind(event_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }
}
fn reject_symlink(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => ensure!(
            !meta.file_type().is_symlink() && meta.is_file(),
            "state file must be a regular file"
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
fn private_file(path: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn status_reads_committed_state_while_writer_holds_lock() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let mut writer = LocalState::open(directory.path()).await?;
        let asset_id = Uuid::new_v4();
        writer.bind(asset_id).await?;
        writer.new_epoch().await?;
        sqlx::query(
            "UPDATE local_identity SET collection_sequence=9,metric_sequence=3,overflow_count=2",
        )
        .execute(&writer.pool)
        .await?;
        let event_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO pending_events(id,sequence,subject,payload) VALUES($1,3,'fixture.event',$2)")
            .bind(&event_id).bind(b"fixture payload".as_slice()).execute(&writer.pool).await?;
        let identity_query = "SELECT id,asset_id,active_epoch,collection_sequence,metric_sequence,overflow_count,create_time,update_time FROM local_identity";
        type IdentitySnapshot = (String, Option<String>, i64, i64, i64, i64, String, String);
        let before: IdentitySnapshot = sqlx::query_as(identity_query)
            .fetch_one(&writer.pool)
            .await?;
        let queued = writer.next().await?;

        // Keep both the process lock and an uncommitted SQLite write transaction
        // active. A status reader must see the previous committed WAL snapshot.
        let mut transaction = writer.pool.begin().await?;
        sqlx::query("UPDATE local_identity SET overflow_count=99")
            .execute(&mut *transaction)
            .await?;
        let status =
            tokio::time::timeout(Duration::from_secs(2), read_status(directory.path())).await??;
        transaction.rollback().await?;
        assert_eq!(status.installation_id, writer.identity.installation_id);
        assert_eq!(status.asset_id, Some(asset_id));
        assert_eq!(
            status.public_key,
            hex::encode(writer.identity.key.verifying_key().to_bytes())
        );
        assert_eq!(status.queue.pending_events, 1);
        assert_eq!(status.queue.pending_bytes, b"fixture payload".len() as i64);
        assert_eq!(status.queue.overflow_count, 2);
        assert_eq!(status.queue.max_events, MAX_QUEUE_EVENTS);
        assert_eq!(status.queue.max_bytes, MAX_QUEUE_BYTES);
        let public = serde_json::to_value(&status)?;
        assert!(public.get("signing_seed").is_none());
        assert!(public.get("key").is_none());
        let after: IdentitySnapshot = sqlx::query_as(identity_query)
            .fetch_one(&writer.pool)
            .await?;
        assert_eq!(
            before, after,
            "status must not change identity metadata or counters"
        );
        assert_eq!(
            queued,
            writer.next().await?,
            "status must not change queued events"
        );
        assert!(
            LocalState::open(directory.path()).await.is_err(),
            "a second writer must still be rejected"
        );

        writer.acknowledge(&event_id).await?;
        assert_eq!(read_status(directory.path()).await?.queue.pending_events, 0);
        writer.pool.close().await;
        Ok(())
    }

    #[tokio::test]
    async fn status_rejects_missing_state_without_creating_files() -> Result<()> {
        let parent = tempfile::tempdir()?;
        let missing = parent.path().join("missing").join("scout");
        assert!(read_status(&missing).await.is_err());
        assert_eq!(std::fs::read_dir(parent.path())?.count(), 0);

        let empty = parent.path().join("empty");
        std::fs::create_dir(&empty)?;
        assert!(read_status(&empty).await.is_err());
        assert_eq!(std::fs::read_dir(&empty)?.count(), 0);

        // An existing but uninitialized database is not permission to bootstrap.
        let database = empty.join("state.sqlite3");
        std::fs::write(&database, [])?;
        assert!(read_status(&empty).await.is_err());
        assert_eq!(std::fs::metadata(&database)?.len(), 0);
        assert_eq!(std::fs::read_dir(&empty)?.count(), 1);
        Ok(())
    }
}
