use anyhow::Result;
use sqlx::{PgPool, Postgres, Transaction, postgres::PgPoolOptions};
use std::time::Duration;
use uuid::Uuid;

pub async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|conn, _| {
            Box::pin(async move {
                sqlx::query("SET search_path = sentinel, public, pg_catalog")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("SET statement_timeout = '15s'")
                    .execute(&mut *conn)
                    .await?;
                sqlx::query("SET lock_timeout = '5s'")
                    .execute(&mut *conn)
                    .await?;
                Ok(())
            })
        })
        .connect(url)
        .await?)
}
pub async fn migrate(pool: &PgPool) -> Result<()> {
    // SQLx 0.8 creates its unqualified ledger in current_schema. Keep that schema
    // stable before and after sentinel is first created; use one pinned connection.
    let mut conn = pool.acquire().await?;
    sqlx::query("SET search_path = public, pg_catalog")
        .execute(&mut *conn)
        .await?;
    let result = sqlx::migrate!("../../migrations").run(&mut *conn).await;
    sqlx::query("SET search_path = sentinel, public, pg_catalog")
        .execute(&mut *conn)
        .await?;
    result?;
    Ok(())
}

pub async fn bootstrap(pool: &PgPool) -> Result<(Uuid, Uuid)> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(524301)")
        .execute(&mut *tx)
        .await?;
    let admin = match sqlx::query_scalar::<_,Uuid>("SELECT id FROM users WHERE display_name = 'Development administrator' AND NOT \"delete\" ORDER BY create_time LIMIT 1").fetch_optional(&mut *tx).await? {
        Some(id) => id,
        None => {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO users(id,display_name) VALUES ($1,'Development administrator')").bind(id).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO role_bindings(id,user_id,role_code,scope_kind) VALUES ($1,$2,'admin','global')").bind(Uuid::new_v4()).bind(id).execute(&mut *tx).await?;
            id
        }
    };
    let group = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM asset_groups WHERE name = 'Default' AND NOT \"delete\"",
    )
    .fetch_optional(&mut *tx)
    .await?
    {
        Some(id) => id,
        None => {
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO asset_groups(id,name) VALUES ($1,'Default')")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            id
        }
    };
    tx.commit().await?;
    Ok((admin, group))
}
pub async fn audit(
    tx: &mut Transaction<'_, Postgres>,
    user: Uuid,
    action: &str,
    asset: Option<Uuid>,
    target: &str,
) -> Result<()> {
    sqlx::query("INSERT INTO audit_events(id,actor_kind,actor_user_id,action,asset_id,target_type,target_id,outcome) VALUES ($1,'user',$2,$3,$4,'management',$5,'succeeded')")
        .bind(Uuid::new_v4()).bind(user).bind(action).bind(asset).bind(target).execute(&mut **tx).await?;
    Ok(())
}
