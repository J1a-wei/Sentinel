use crate::db;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use chrono::Utc;
use sentinel_protocol::{bounded, decode_key, hash};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use subtle::ConstantTimeEq;
use tower_http::{
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub token_hash: [u8; 32],
    pub admin_id: Uuid,
    pub default_group: Uuid,
    pub ready: Arc<AtomicBool>,
}
pub struct ApiError(StatusCode, &'static str);
type ApiResult<T> = Result<T, ApiError>;
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error":self.1}))).into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &e
            && db.code().is_some_and(|c| c.starts_with("23"))
        {
            return Self(StatusCode::CONFLICT, "constraint_conflict");
        }
        tracing::warn!(error_kind = "database", "management request failed");
        Self(StatusCode::SERVICE_UNAVAILABLE, "database_unavailable")
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid_request")
    }
}
pub fn router(state: AppState, web: PathBuf) -> Router {
    let api = Router::new()
        .route("/session", get(session))
        .route("/capabilities", get(capabilities))
        .route("/assets", get(assets))
        .route("/assets/{id}", get(asset).patch(update_asset))
        .route("/groups", get(groups).post(create_group))
        .route("/installations", post(enroll))
        .route("/installations/{id}/revoke", post(revoke))
        .route("/tasks", get(tasks).post(unavailable))
        .route("/upgrades", get(upgrades).post(unavailable))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "not_found") })
        .layer(middleware::from_fn_with_state(state.clone(), authorize));
    Router::new().route("/healthz",get(|| async { Json(json!({"status":"alive"})) }))
        .route("/readyz",get(ready))
        .nest("/api/v1",api)
        .fallback_service(ServeDir::new(&web).not_found_service(ServeFile::new(web.join("index.html"))))
        .layer(DefaultBodyLimit::max(32_768))
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT,Duration::from_secs(20)))
        .layer(SetResponseHeaderLayer::overriding(header::CACHE_CONTROL,HeaderValue::from_static("no-store")))
        .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS,HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY,HeaderValue::from_static("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'")))
        .with_state(state)
}
async fn authorize(State(s): State<AppState>, req: Request, next: Next) -> Response {
    let valid = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| !v.is_empty())
        .is_some_and(|v| bool::from(hash(v.as_bytes()).ct_eq(&s.token_hash)));
    if !valid {
        return ApiError(StatusCode::UNAUTHORIZED, "unauthorized").into_response();
    }
    let allowed = sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM users u JOIN role_bindings r ON r.user_id=u.id AND NOT r.\"delete\" WHERE u.id=$1 AND u.status='active' AND NOT u.\"delete\" AND r.role_code='admin' AND r.scope_kind='global')").bind(s.admin_id).fetch_one(&s.pool).await;
    match allowed {
        Ok(true) => next.run(req).await,
        Ok(false) => ApiError(StatusCode::FORBIDDEN, "administrator_disabled").into_response(),
        Err(e) => ApiError::from(e).into_response(),
    }
}
async fn session() -> Json<Value> {
    Json(json!({"role":"admin","mode":"development","authentication":"administrator_token"}))
}
async fn capabilities() -> Json<Value> {
    Json(
        json!({"inventory":true,"read_only":true,"vulnerability_matching":false,"baseline":false,"ai":false,"remote_execution":false,"upgrades":false,"metric_history":false,"task_execution":false}),
    )
}
async fn ready(State(s): State<AppState>) -> Response {
    let db = sqlx::query("SELECT 1").execute(&s.pool).await.is_ok();
    if db && s.ready.load(Ordering::Relaxed) {
        Json(json!({"status":"ready"})).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"not_ready"})),
        )
            .into_response()
    }
}
#[derive(Deserialize, Default)]
struct AssetQuery {
    after: Option<Uuid>,
    group_id: Option<Uuid>,
    q: Option<String>,
    limit: Option<i64>,
}
const ASSET_SELECT: &str = r#"
SELECT jsonb_build_object('id',a.id,'display_name',a.display_name,'group_id',g.id,'group_name',g.name,'lifecycle',a.lifecycle,
 'tags',COALESCE((SELECT jsonb_object_agg(t.key,t.value) FROM asset_tags t WHERE t.asset_id=a.id AND NOT t."delete"),'{}'::jsonb),
 'metrics',CASE WHEN m.id IS NULL THEN NULL ELSE to_jsonb(m) - 'id' - 'create_time' - 'update_time' - 'delete' END,
 'last_seen_at',si.last_seen_at,'scout_version',si.version,
 'freshness',CASE WHEN m.observed_at > now() + interval '5 minutes' THEN 'unknown' WHEN m.observed_at > now() - interval '2 minutes' THEN 'fresh' WHEN m.id IS NOT NULL THEN 'stale' ELSE 'unknown' END,
 'hostname',inv.hostname,'os_id',inv.os_id,'os_version',inv.os_version)
FROM assets a JOIN asset_groups g ON g.id=a.group_id AND NOT g."delete"
LEFT JOIN scout_installations ins ON ins.asset_id=a.id AND ins.status='active' AND NOT ins."delete"
LEFT JOIN scout_instances si ON si.installation_id=ins.id AND si.role='active' AND NOT si."delete"
LEFT JOIN asset_metric_latest m ON m.asset_id=a.id AND NOT m."delete" AND m.instance_id=si.id
LEFT JOIN asset_collection_heads h ON h.asset_id=a.id AND h.kind='inventory' AND h.scope_key='host' AND NOT h."delete"
LEFT JOIN collection_runs cr ON cr.id=h.latest_attempt_id AND NOT cr."delete" AND cr.installation_id=ins.id
LEFT JOIN asset_inventory_snapshots inv ON inv.collection_run_id=cr.id AND NOT inv."delete"
WHERE NOT a."delete"
"#;
async fn assets(State(s): State<AppState>, Query(q): Query<AssetQuery>) -> ApiResult<Json<Value>> {
    if q.q.as_ref().is_some_and(|v| v.len() > 128) {
        return Err(ApiError(StatusCode::BAD_REQUEST, "search_too_long"));
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 100);
    let sql = format!(
        "{ASSET_SELECT} AND ($1::uuid IS NULL OR a.id>$1) AND ($2::uuid IS NULL OR a.group_id=$2) AND ($3::text IS NULL OR strpos(lower(a.display_name),lower($3))>0) ORDER BY a.id LIMIT $4"
    );
    let mut items: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(q.after)
        .bind(q.group_id)
        .bind(q.q)
        .bind(limit + 1)
        .fetch_all(&s.pool)
        .await?;
    let more = items.len() > limit as usize;
    items.truncate(limit as usize);
    let next = if more {
        items.last().and_then(|v| v.get("id")).cloned()
    } else {
        None
    };
    Ok(Json(
        json!({"items":items,"next_cursor":next,"server_time":Utc::now()}),
    ))
}
async fn asset(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let sql = format!("{ASSET_SELECT} AND a.id=$1");
    let item: Value = sqlx::query_scalar(&sql)
        .bind(id)
        .fetch_optional(&s.pool)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "asset_not_found"))?;
    let collections:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('kind',h.kind,'latest_attempt',jsonb_build_object('id',r.id,'status',r.status,'coverage',r.coverage,'observed_at',r.finished_at,'sequence',r.sequence),'latest_complete',CASE WHEN c.id IS NULL THEN NULL ELSE jsonb_build_object('id',c.id,'observed_at',c.finished_at,'sequence',c.sequence) END) FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id AND NOT r."delete" JOIN scout_installations si ON si.id=r.installation_id AND NOT si."delete" AND si.status='active' LEFT JOIN collection_runs c ON c.id=h.latest_complete_id AND NOT c."delete" WHERE h.asset_id=$1 AND NOT h."delete" ORDER BY h.kind"#).bind(id).fetch_all(&s.pool).await?;
    let inventory:Option<Value>=sqlx::query_scalar(r#"SELECT to_jsonb(i)-'create_time'-'update_time'-'delete' FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id AND NOT r."delete" JOIN scout_installations si ON si.id=r.installation_id AND NOT si."delete" AND si.status='active' JOIN asset_inventory_snapshots i ON i.collection_run_id=r.id AND NOT i."delete" WHERE h.asset_id=$1 AND h.kind='inventory' AND h.scope_key='host' AND NOT h."delete""#).bind(id).fetch_optional(&s.pool).await?;
    let processes:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('pid',p.pid,'start_ticks',p.start_ticks,'name',p.name,'state',p.state) FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id AND NOT r."delete" JOIN scout_installations si ON si.id=r.installation_id AND NOT si."delete" AND si.status='active' JOIN process_snapshot_entries p ON p.collection_run_id=r.id AND NOT p."delete" WHERE h.asset_id=$1 AND h.kind='inventory' AND NOT h."delete" ORDER BY p.pid LIMIT 8000"#).bind(id).fetch_all(&s.pool).await?;
    let ports:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('protocol',p.protocol,'address',host(p.local_address),'port',p.local_port,'network_namespace',p.network_namespace,'loopback',(p.local_address <<= '127.0.0.0/8'::inet OR p.local_address='::1'::inet)) FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id AND NOT r."delete" JOIN scout_installations si ON si.id=r.installation_id AND NOT si."delete" AND si.status='active' JOIN port_snapshot_endpoints p ON p.collection_run_id=r.id AND NOT p."delete" WHERE h.asset_id=$1 AND h.kind='ports' AND NOT h."delete" ORDER BY p.protocol,p.local_port,p.local_address LIMIT 8000"#).bind(id).fetch_all(&s.pool).await?;
    let packages:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('name',p.package_name,'version',p.version,'architecture',p.architecture,'source_name',p.source_name,'source_version',p.source_version,'origin',p.origin_status) FROM asset_collection_heads h JOIN collection_runs r ON r.id=h.latest_attempt_id AND NOT r."delete" JOIN scout_installations si ON si.id=r.installation_id AND NOT si."delete" AND si.status='active' JOIN package_snapshots ps ON ps.id=r.package_snapshot_id AND NOT ps."delete" JOIN package_entries p ON p.snapshot_id=ps.id AND NOT p."delete" WHERE h.asset_id=$1 AND h.kind='packages' AND NOT h."delete" ORDER BY p.package_name,p.architecture LIMIT 20000"#).bind(id).fetch_all(&s.pool).await?;
    let conflicts:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('id',c.id,'reason_code',c.reason_code,'detected_at',c.detected_at,'state',c.state) FROM identity_conflicts c JOIN assets a ON a.id=c.asset_id AND NOT a."delete" LEFT JOIN assets b ON b.id=c.other_asset_id AND NOT b."delete" WHERE (c.asset_id=$1 OR c.other_asset_id=$1) AND NOT c."delete" AND c.state='open' AND (c.other_asset_id IS NULL OR b.id IS NOT NULL) ORDER BY c.detected_at DESC LIMIT 100"#).bind(id).fetch_all(&s.pool).await?;
    Ok(Json(
        json!({"asset":item,"inventory":inventory,"identity_conflicts":conflicts,"collections":collections,"processes":processes,"ports":ports,"packages":packages,"server_time":Utc::now()}),
    ))
}
async fn groups(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    let rows:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'name',name,'description',description) FROM asset_groups WHERE NOT \"delete\" ORDER BY name LIMIT 1000").fetch_all(&s.pool).await?;
    Ok(Json(json!({"items":rows})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupInput {
    name: String,
    #[serde(default)]
    description: String,
}
async fn create_group(
    State(s): State<AppState>,
    Json(g): Json<GroupInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    bounded(g.name.trim(), 80)?;
    if g.description.len() > 512 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "description_too_long"));
    }
    let mut tx = s.pool.begin().await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO asset_groups(id,name,description) VALUES($1,$2,$3)")
        .bind(id)
        .bind(g.name.trim())
        .bind(g.description)
        .execute(&mut *tx)
        .await?;
    db::audit(&mut tx, s.admin_id, "group.create", None, &id.to_string()).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({"id":id}))))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetUpdate {
    display_name: Option<String>,
    group_id: Option<Uuid>,
    tags: Option<BTreeMap<String, String>>,
}
async fn update_asset(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(input): Json<AssetUpdate>,
) -> ApiResult<Json<Value>> {
    if let Some(name) = &input.display_name {
        bounded(name.trim(), 128)?;
    }
    if let Some(tags) = &input.tags {
        if tags.len() > 32 {
            return Err(ApiError(StatusCode::BAD_REQUEST, "too_many_tags"));
        }
        for (k, v) in tags {
            bounded(k, 64)?;
            if v.len() > 128 || v.chars().any(char::is_control) {
                return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_tag"));
            }
        }
    }
    let mut tx = s.pool.begin().await?;
    let found=sqlx::query_scalar::<_,Uuid>("SELECT a.id FROM assets a JOIN asset_groups g ON g.id=a.group_id AND NOT g.\"delete\" WHERE a.id=$1 AND NOT a.\"delete\" FOR UPDATE OF a").bind(id).fetch_optional(&mut *tx).await?;
    if found.is_none() {
        return Err(ApiError(StatusCode::NOT_FOUND, "asset_not_found"));
    }
    if let Some(group) = input.group_id {
        let exists = sqlx::query_scalar::<_, Uuid>(
            "SELECT id FROM asset_groups WHERE id=$1 AND NOT \"delete\" FOR SHARE",
        )
        .bind(group)
        .fetch_optional(&mut *tx)
        .await?;
        if exists.is_none() {
            return Err(ApiError(StatusCode::BAD_REQUEST, "group_not_found"));
        }
    }
    sqlx::query("UPDATE assets SET display_name=COALESCE($2,display_name),group_id=COALESCE($3,group_id) WHERE id=$1").bind(id).bind(input.display_name.map(|n|n.trim().to_owned())).bind(input.group_id).execute(&mut *tx).await?;
    if let Some(tags) = input.tags {
        sqlx::query("UPDATE asset_tags SET \"delete\"=true WHERE asset_id=$1 AND NOT \"delete\"")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        for (k, v) in tags {
            sqlx::query("INSERT INTO asset_tags(id,asset_id,key,value) VALUES($1,$2,$3,$4)")
                .bind(Uuid::new_v4())
                .bind(id)
                .bind(k)
                .bind(v)
                .execute(&mut *tx)
                .await?;
        }
    }
    db::audit(
        &mut tx,
        s.admin_id,
        "asset.update",
        Some(id),
        &id.to_string(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    installation_id: Uuid,
    public_key: String,
    display_name: String,
    group_id: Option<Uuid>,
}
async fn enroll(State(s): State<AppState>, Json(e): Json<Enrollment>) -> ApiResult<Json<Value>> {
    bounded(e.display_name.trim(), 128)?;
    if e.installation_id.is_nil() {
        return Err(ApiError(StatusCode::BAD_REQUEST, "invalid_installation_id"));
    }
    let key = decode_key(&e.public_key)?;
    let digest = hash(&key.to_bytes());
    let mut tx = s.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(524302)")
        .execute(&mut *tx)
        .await?;
    if let Some(row)=sqlx::query("SELECT i.asset_id,i.status,NOT i.\"delete\" AND NOT a.\"delete\" AND NOT g.\"delete\" AND a.lifecycle='active' AS live FROM scout_installations i JOIN assets a ON a.id=i.asset_id JOIN asset_groups g ON g.id=a.group_id WHERE i.id=$1 FOR UPDATE OF i").bind(e.installation_id).fetch_optional(&mut *tx).await? {
        let same=sqlx::query_scalar::<_,bool>("SELECT EXISTS(SELECT 1 FROM scout_credentials WHERE installation_id=$1 AND public_key_sha256=$2 AND NOT \"delete\" AND revoked_at IS NULL AND valid_from<=now() AND valid_until>now())").bind(e.installation_id).bind(digest.to_vec()).fetch_one(&mut *tx).await?;
        if !same || row.get::<String,_>("status")!="active" || !row.get::<bool,_>("live") { return Err(ApiError(StatusCode::CONFLICT,"installation_binding_conflict")); }
        let asset_id:Uuid=row.get("asset_id"); tx.commit().await?;
        return Ok(Json(json!({"asset_id":asset_id,"installation_id":e.installation_id})));
    }
    // A copied public key cannot silently create a second asset.
    let reused = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM scout_credentials WHERE public_key_sha256=$1)",
    )
    .bind(digest.to_vec())
    .fetch_one(&mut *tx)
    .await?;
    if reused {
        return Err(ApiError(
            StatusCode::CONFLICT,
            "public_key_already_registered",
        ));
    }
    let group = e.group_id.unwrap_or(s.default_group);
    if sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM asset_groups WHERE id=$1 AND NOT \"delete\" FOR SHARE",
    )
    .bind(group)
    .fetch_optional(&mut *tx)
    .await?
    .is_none()
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "group_not_found"));
    }
    let asset_id = Uuid::new_v4();
    sqlx::query("INSERT INTO assets(id,group_id,display_name) VALUES($1,$2,$3)")
        .bind(asset_id)
        .bind(group)
        .bind(e.display_name.trim())
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO scout_installations(id,asset_id,generation,status) VALUES($1,$2,1,'active')",
    )
    .bind(e.installation_id)
    .bind(asset_id)
    .execute(&mut *tx)
    .await?;
    let credential_hash = hash(
        format!(
            "sentinel-ed25519-v1:{}:{}",
            e.installation_id,
            hex::encode(key.to_bytes())
        )
        .as_bytes(),
    );
    sqlx::query("INSERT INTO scout_credentials(id,installation_id,credential_sha256,public_key_sha256,issuer_reference,valid_from,valid_until) VALUES($1,$2,$3,$4,'sentinel:ed25519:v1',now(),now()+interval '365 days')").bind(Uuid::new_v4()).bind(e.installation_id).bind(credential_hash.to_vec()).bind(digest.to_vec()).execute(&mut *tx).await?;
    db::audit(
        &mut tx,
        s.admin_id,
        "installation.enroll",
        Some(asset_id),
        &e.installation_id.to_string(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(
        json!({"asset_id":asset_id,"installation_id":e.installation_id}),
    ))
}
async fn revoke(State(s): State<AppState>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let mut tx = s.pool.begin().await?;
    let asset=sqlx::query_scalar::<_,Uuid>("SELECT i.asset_id FROM scout_installations i JOIN assets a ON a.id=i.asset_id AND NOT a.\"delete\" JOIN asset_groups g ON g.id=a.group_id AND NOT g.\"delete\" WHERE i.id=$1 AND NOT i.\"delete\" FOR UPDATE OF i,a").bind(id).fetch_optional(&mut *tx).await?.ok_or(ApiError(StatusCode::NOT_FOUND,"installation_not_found"))?;
    sqlx::query("UPDATE scout_installations SET status='revoked',revoked_at=COALESCE(revoked_at,now()) WHERE id=$1").bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE scout_credentials SET revoked_at=COALESCE(revoked_at,now()) WHERE installation_id=$1 AND NOT \"delete\"").bind(id).execute(&mut *tx).await?;
    db::audit(
        &mut tx,
        s.admin_id,
        "installation.revoke",
        Some(asset),
        &id.to_string(),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"installation_id":id,"status":"revoked"})))
}
async fn unavailable() -> ApiError {
    ApiError(StatusCode::NOT_IMPLEMENTED, "not_implemented")
}
async fn tasks(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    let items:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('id',t.id,'asset_id',t.asset_id,'kind',t.kind,'state',t.state) FROM tasks t JOIN assets a ON a.id=t.asset_id AND NOT a."delete" JOIN asset_groups g ON g.id=a.group_id AND NOT g."delete" WHERE NOT t."delete" ORDER BY t.create_time DESC,t.id LIMIT 100"#).fetch_all(&s.pool).await?;
    Ok(Json(json!({"items":items,"execution_available":false})))
}
async fn upgrades(State(s): State<AppState>) -> ApiResult<Json<Value>> {
    let items:Vec<Value>=sqlx::query_scalar(r#"SELECT jsonb_build_object('id',u.id,'state',u.state,'create_time',u.create_time) FROM upgrade_rollouts u WHERE NOT u."delete" ORDER BY u.create_time DESC,u.id LIMIT 100"#).fetch_all(&s.pool).await?;
    Ok(Json(json!({"items":items,"execution_available":false})))
}
