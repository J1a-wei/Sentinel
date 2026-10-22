# 一期 A 开发接口约定

状态：一期 A 开发闭环已实现并通过下列本地验证；此文件记录本批接口，不代表原设计中的全部能力已经实现。A 维护本文件，B/DevOps 可据此并行。

## 构建与进程

- Rust **1.97.1**，edition **2024**，MSRV 1.97；工具在 `/home/ubuntu/.cargo/bin`。
- Cargo workspace：`crates/protocol`、`crates/hub`、`crates/scout`；二进制名 **hub**、**scout**。
- `cargo build --workspace --locked`；发布构建 `cargo build --release --locked --bin hub --bin scout`。
- Web：Vue 3 + TypeScript + Vite，Node 22+，`cd web && npm ci && npm run build`，输出 `web/dist`。Hub 用 `SENTINEL_WEB_DIR` 托管该目录；Docker hub target 需要复制构建产物。
- `hub` 启动时执行 SQLx 版本迁移；`hub migrate` 只执行迁移后退出；`hub health` 检查本地健康端点并通过退出码报告。
- `scout init` 生成持久身份并输出公开登记信息；`scout enroll` 使用管理凭证登记（可重试），`scout` 开始采集与补传；`scout once` 采集一批并尝试发送，未获发布确认仍保留队列；`scout status` 只读现有 SQLite，输出公开身份和同一已提交快照中的队列状态，常驻 Scout 持有写锁时也可查询。status 不创建目录/身份、不迁移、不获取 `active.lock`、不修改 epoch/序号；状态缺失或不兼容时非零退出，初始化仍需显式 `scout init`。写进程继续独占状态目录。
- `scout doctor` 只读诊断当前进程运行环境和采集路径，不打开状态、不生成身份、不登记、不读取管理员/NATS 凭证、不连接 Hub/NATS。可输出 JSON 后非零退出，具体规则见下文。`status` 的四个顶层字段和既有输出保持不变，`init`/`enroll`/`status` 不依赖采集环境配置。
- SIGINT/SIGTERM 协调退出；无远程 Shell、密码破解或自动处置。

## 环境配置

| 进程 | 环境变量 | 默认/规则 |
| --- | --- | --- |
| Hub | `SENTINEL_DATABASE_URL` | 必填 PostgreSQL 连接串；数据库 17+ |
| Hub | `SENTINEL_ADMIN_TOKEN` | 必填且至少 32 字符，不允许空凭证；支持 `SENTINEL_ADMIN_TOKEN_FILE`，与直接变量互斥；本批单管理员开发模式 |
| Hub | `SENTINEL_BIND` | `127.0.0.1:8080`；容器内部可显式 `0.0.0.0:8080`，宿主端口只映射 loopback |
| Hub | `SENTINEL_WEB_DIR` | `web/dist` |
| Hub/Scout | `SENTINEL_NATS_URL` | `nats://127.0.0.1:4222` |
| Hub/Scout | `SENTINEL_NATS_TOKEN` | 可选传输认证；支持 `SENTINEL_NATS_TOKEN_FILE`，与直接变量互斥；仅 loopback 隔离开发环境允许不设 |
| Scout | `SENTINEL_STATE_DIR` | `./var/scout`；专用持久可写目录，权限 0700 |
| Scout | `SENTINEL_RUNTIME_MODE` | `auto`；允许 `auto` / `native` / `container`，自动探测当前进程实际根下的运行环境线索 |
| Scout | `SENTINEL_HOST_ROOT` | 可选显式采集根，优先于模式默认值；未设置时 native 为 `/`、container 为 `/host`，auto 无法判断时不选择默认根；不存在绝不回落，推荐绝对路径 |
| Scout | `SENTINEL_NETWORK_PROC_PREFIX` | `proc/1/net`；采集根内的相对路径，拒绝空值、绝对路径、空组件、`.`、`..`、控制字符和超过 256 字节的值；显式来源缺失不回落 |
| Scout | `SENTINEL_HUB_URL` | `http://127.0.0.1:8080`；仅登记时使用 |
| Scout enroll | `SENTINEL_ADMIN_TOKEN` | 只用于管理员授权登记；常驻 Scout 无需该凭证 |
| Scout enroll | `SENTINEL_ASSET_NAME` | 可选显示名，默认安装 ID；`SENTINEL_GROUP_ID` 可选 |
| Scout | `SENTINEL_INTERVAL_SECONDS` | `30`，范围 5..3600 |
| 全部 | `RUST_LOG` | 默认 `info`，tracing JSON；不记录密钥或原始主机清单 |

开发环境 HTTP/NATS 明文只适用于受控 loopback 网络。跨主机部署须提供 TLS 终止、NATS TLS/权限及凭证管理；本批不声称生产部署能力。Scout 容器只读挂载 `/proc`、`/sys`、`/etc`、dpkg 数据目录到 `/host`；本批不需要 Docker socket。宿主网络视图需显式配置，覆盖不充分报告 unknown/partial。

### Scout 运行环境选择与 doctor

- 探测始终针对当前进程实际 `/`，不针对 `SENTINEL_HOST_ROOT`。检查 `/.dockerenv`、`/run/.containerenv`、`/run/systemd/container`，以及 [systemd 容器接口](https://systemd.io/CONTAINER_INTERFACE/)约定的 `/run/host/container-manager`；容器标记优先，使用宿主 PID/cgroup 视图也不会覆盖这些标记。
- 只读 `/proc/self/cgroup` 和 `/proc/1/cgroup` 中的 Docker、Podman、Kubernetes/CRI、LXC 路径线索。每份 cgroup 最多读取 64 KiB、解析 128 行，文本标记最多 256 字节；读取在单个阻塞任务中执行，外层期限 5 秒。不读取进程环境、机器身份或凭证来探测，也不执行外部命令。
- 标记均明确不存在、self cgroup 格式有效且存在受支持的 systemd 原生层级（`system.slice`、`user.slice`、`init.scope`），并且没有容器线索时，自动选 native。self cgroup 缺失/不可读/格式异常/仅根路径 `/`/层级未识别，或容器标记不能确认时，不直接推断 native，报告 unknown。PID 1 cgroup 作为额外容器线索；它不可用时记录原因，仍可使用有效的 self cgroup 判断。该判断是有限线索的启发式结果，不是宿主身份认证；刻意隐藏标记/重写层级的运行环境仍须管理员核对。
- `SENTINEL_RUNTIME_MODE=native|container` 显式选择模式，保留实际 `detected_runtime` 供检查；显式 `SENTINEL_HOST_ROOT` 优先，允许 fixture/特殊挂载，也允许在 detected unknown 时明确指定采集根。检测到容器或选择 container 时，采集根不能等于当前进程根（含符号链接或同设备/inode 的同根挂载），强制 native 也不会绕过已检测到的容器根保护。
- auto unknown 且没有显式采集根、根缺失/不是目录/不可访问、容器根保护触发、容器的采集根中缺少可访问且未逃逸的 `proc` 目录时，`scout` / `once` 在打开本地状态前拒绝启动。缺少个别采集文件仍由各采集器报告缺失/partial；不使用容器自身路径补齐。
- 默认网络来源为 `<host_root>/proc/1/net`。覆盖为 `proc/net` / `proc/self/net` 时仍保留采集器对网络视图的限制说明；路径存在不代表已确认宿主网络命名空间。缺少显式网络来源时 doctor 报告原因，采集可继续并产生缺失覆盖。
- doctor JSON 字段：`detected_runtime`（native/container/unknown）、`requested_mode`、`selected_mode`、`host_root`（未选择为 null）、`host_root_explicit`、`host_root_status`、`network_proc_prefix`、`network_source`、`network_source_status`、`collection_allowed`、有限枚举 `reasons`。原因不会包含原始 cgroup、标记内容、进程环境或机器信息。`collection_allowed=true` 只表示通过路径选择的启动前检查，不保证每个挂载或采集域完整。
- doctor 对合法配置总是先输出上述 JSON；`collection_allowed=false` 时非零退出。模式/路径格式非法或诊断工作超时时非零退出并提供静态错误，不输出伪造报告。systemd 环境示例保持 `SENTINEL_RUNTIME_MODE=auto`，默认不强制 `SENTINEL_HOST_ROOT=/`；可先运行 doctor，再根据实际环境显式覆盖。

## HTTP 与授权

- `GET /healthz`：最小存活响应；`GET /readyz`：数据库及消费循环就绪状态。无敏感信息、不提供控制操作。
- `/api/v1/*` 必须 `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>`；空/错误凭证返回 401。
- `GET /api/v1/session`：验证凭证与开发模式能力；UI 凭证仅保存在页面内存，退出/刷新清除。
- `GET /api/v1/assets`、`GET /api/v1/assets/{id}`：真实资产、当前采集和覆盖；无数据为 null/空集合，未完成检查不计作通过。
- `GET/POST /api/v1/groups`、`PATCH /api/v1/assets/{id}`：分组和标签；名称、数量和长度有界，引用必须存活。
- `POST /api/v1/installations`：输入 `installation_id` UUID、`public_key` Ed25519 公钥 hex、`display_name`、可选 `group_id`；输出 `asset_id`、`installation_id`。重复相同登记返回原绑定；同 ID 不同密钥拒绝。
- `GET /api/v1/capabilities`：明确漏洞匹配、基线、AI、升级和任务执行未接入。
- 任务/升级写接口返回 501/明确 `not_implemented`，不生成假成功；状态查询仅返回真实数据库记录。

## 消息和数据库

- JetStream stream `SENTINEL_EVENTS`，subject `sentinel.events.<installation_id>`，文件存储，durable consumer `hub-inventory-v1`，显式 ACK。
- 事件 `SignedEvent { public_key, payload, signature }`：公钥/签名 hex，payload 是 UTF-8 JSON 字符串；Ed25519 签名覆盖原始 payload 字节。Hub 验证公钥摘要、有效期、安装状态、asset 绑定和 subject；不能靠自报 asset 获授权。
- 本地 SQLite 分配持久递增 sequence 并保存带稳定 event_id 的完整已签名事件。发布确认后出队；未确认重复发送保留 event_id。禁止覆盖/清空未知队列。
- Hub inbox 与原有领域表同事务提交，提交后 ACK；重复 event_id 摘要不同报冲突，乱序不回退当前指针。无效消息终止重投并结构化记录原因，不记录 payload。
- `migrations/0001_inventory.sql`、`0002_control.sql`、`0003_assessments.sql` 从既有三份 SQL 复制，去掉外层 BEGIN/COMMIT（SQLx 提供事务），并在迁移 search_path 中保留 public，使 SQLx 能在同一事务写入其 `_sqlx_migrations` 账本。保留原草案及 `docs/sql/verify.sql`。
- 复用资产、安装、凭证、实例、collection_runs、inventory/package/port snapshots、heads、asset_metric_latest、inbox。`0004_process_inventory.sql` 增加专用进程明细关系表，有四通用字段/单列 UUID 主键/元数据触发器及跨资产约束。不建通用 JSON 影子表。
- 当前指标和有界清单先落地；历史聚合、保留调度、自动升级/任务执行本批未接入，界面明确提示。

## B 采集器适配

- B 仅维护 `crates/scout/src/collectors/**`，入口 `mod.rs`，自定义 serde DTO；A 负责 `pub mod collectors`、调用及协议转换。
- 请尽快提供 `collect(root: &Path)` 或相等入口及 DTO 名称；同步只读采集在单个 `spawn_blocking` 工作中调用，A 保证不并发叠加。
- 每类结果须带 coverage/status/reason；数据来源限定 fixture 或显式 host root。不得读取 shadow、完整命令行、环境变量或真实用户敏感数据。
- 尽量提供主机/OS、CPU 原始计数、meminfo、网卡计数、TCP LISTEN/UDP bind、PID+start ticks+名称+状态、完整 dpkg 版本/源包/架构。CPU/网络速率由相邻有效采样计算，首次/重置为 null。

## 验证交接

运行 Rust fmt/build/test/clippy（locked），Web 类型检查和生产构建；连接测试环境后执行原 SQL 验证、身份/签名错误、重复及乱序、软删除和跨资产约束检查。环境不足明确报告，不把静态检查写成端到端测试通过。所有文件保留工作区未提交状态，不 push 或发布。

## 实现补充（集成中）

- 本地队列限制 1,000 条、128 MiB payload；SQLite `max_page_count=40960`（默认 4 KiB 页约 160 MiB）、WAL 自动检查点及日志限额。队满不覆盖旧事件，跳过新观测并递增 `overflow_count`，`scout status` 与下一次上报的 `scout_health.queue` 可见。
- 单事件上限 900,000 字节（包含签名信封），超过时按实际编码大小裁剪最大的清单类别，并标记 `partial` / `limit_exceeded`；基础主机和心跳仍可发送。不会把裁剪清单发布成完整结果。
- 网络读取默认 `proc/1/net`，可用 `SENTINEL_NETWORK_PROC_PREFIX` 显式覆盖，测试也提供默认宿主视图。网卡速率依赖同一 boot_id、ifindex、name 与单调时间差；首个样本、计数器回退、编号变化为 unknown。内核快速复用同一 ifindex 与同名接口且计数仍更高的情况不能仅靠这些字段完全识别。
- `etc/machine-id` 只在 Scout 内作 `SHA256("sentinel:machine-id:v1\0" + lowercase_hex_machine_id)` 派生，原值不上报、不记录日志。摘要写既有 `asset_fingerprint_observations`；跨资产相同摘要写 `identity_conflicts`，API/详情提示“发现未处置”，不自动合并或恢复权限。
- `POST /api/v1/installations/{id}/revoke` 真实吊销安装及凭证；同身份后续消息拒绝。
- 当前使用单管理员开发授权，数据库 `users` 和全局 `role_bindings` 参与每次请求授权。尚无组级多用户管理界面。
- 当前资产详情清单有界：包 20,000、进程/端口各 8,000、网卡 256；实际消息预算可能更小。UI 软件包/进程搜索展示匹配结果前 300 条；服务端资产列表按 UUID 游标分页（最多 100）。
- HTTP 命令执行、密码验证、升级执行、AI 调用、漏洞匹配、基线评估、分钟/小时指标聚合、保留任务均未实现；读取任务/升级返回真实表中状态，写请求返回 501。
- HTTP Web 与 API 同源，不开放宽泛 CORS；凭证只保留页面内存。UI 每 30 秒刷新，旧异步响应在导航（含详情返回）/退出后丢弃；保存前固定资产 ID，等待期间导航后不再读取空详情或写回旧详情/成功提示。移动端保留退出入口。

- Scout 本批单文件读取预算为 1 MiB，dpkg status 为 32 MiB，采集一批 20 秒超时、单个阻塞采集工作；超限提供部分覆盖。运行时退出最多等待阻塞工作 5 秒。
- 仅接受从宿主 dpkg arch 文件确认的主机架构；采集器构建架构不是宿主观测证据，缺失时保存 null/unknown。
- SQLx 迁移固定一个 `search_path=public` 连接创建和读取迁移账本，迁移结束恢复应用查询路径。首次安装与重新连接后的迁移都验证幂等。不要手动将 `_sqlx_migrations` 移入 sentinel 业务 schema。

## 本轮实际验证结果

2026-10-21，Rust 1.97.1、原生 PostgreSQL 17.11、NATS JetStream 2.15.1，使用协调者提供的 loopback 测试服务；所有主机输入均为虚构 fixture。

- `cargo fmt --all -- --check`、`cargo build --workspace --locked`、`cargo test --workspace --locked`、`cargo clippy --workspace --all-targets --locked -- -D warnings` 全部通过。status 修复后重跑共 74 个单元测试（Scout 73 + protocol 1）；环境依赖的 Hub 集成测试在普通 test 中忽略，下面记录此前单独运行结果。
- `TEST_DATABASE_URL=... cargo test -p hub --test ingestion --locked -- --ignored` 已单独通过：首次/再次迁移、授权、登记重试、签名篡改、错误 subject、跨资产伪报、同事件 ID 不同正文、重复接收、软删后幂等、乱序 attempt/complete 水位、吊销、跨资产进程 FK、同指纹不同资产冲突线索。
- 对实际四份迁移后的 47 张业务表执行 `docs/sql/verify.sql`，94 断言通过（22 正例 / 72 反例），测试事务回滚。
- Web `npm run build`（包含 vue-tsc）通过；真实 Hub/API 的 Chromium 桌面和 390px 手机检查：凭证登录、资产详情、软件包列表、手机退出、无 WebStorage 凭证、无浏览器 JS 异常。
- 独立虚构链路 `scout init → enroll → once → JetStream → PostgreSQL → API` 通过：4 个端点、2 个软件包、2 个进程；发布确认后持久队列清空，首采 CPU 为 null。
- 常驻 Scout 两次虚构采样端到端通过：CPU 10%，以实际单调间隔计算的网卡接收/发送速率为预期 2:1。单元测试另覆盖首次、重启、计数重置和接口变化。
- status 新增 2 个测试通过：写实例持锁并有未提交 SQLite 事务时读取已提交快照，身份/epoch/序号/队列不变；目录、数据库缺失及未初始化数据库拒绝且无文件创建/初始化。另用实际常驻 Scout 二进制和虚构 host fixture 验证并发 `scout status` 成功、第二个写进程仍被拒绝。
- 返回竞态修复后 Web 类型检查/生产构建通过；独立 Chromium 使用受控虚构 API 响应验证延迟 30 秒刷新后返回、PATCH 等待时返回、保存后详情 GET 等待时返回及正常保存，无空详情异常、旧详情恢复或过期成功提示。

以上验证不是千台容量、生产 TLS/RBAC、容灾或自动升级验收。根目录部署/CI/安装脚本由 DevOps 与协调者另行集成验证。

### 运行环境探测增量验证

- 本轮 `cargo fmt --all -- --check`、`cargo test -p scout --locked`、`cargo clippy -p scout --all-targets --locked -- -D warnings` 通过：Scout 87 个单元测试、3 个 CLI 集成测试；原采集器说明中的 1 个 doc-test 仍为 ignore。
- 新增 14 个 fixture 单测覆盖 native/多类容器标记/cgroup v1 与 v2、宿主 PID/cgroup 下标记优先、unknown 和有界异常输入、显式模式/根优先、防回落、容器自身根及别名拒绝、网络路径覆盖与校验、诊断无原始标记/cgroup 泄漏。
- CLI 测试验证 doctor 无身份/登记/凭证也可运行；状态目录不创建，根缺失时 doctor 输出失败 JSON 且 once 不初始化状态；init/status 忽略采集配置并保持公开身份/队列合同。
- 本机单独执行默认 auto 的 doctor：实际返回 native、采集根 `/`、网络来源 `/proc/1/net`、`collection_allowed=true`，退出 0；未创建指定的空状态目录，未执行主机采集或读取凭证。
- 本轮没有执行全 workspace 构建或端到端测试；由协调者在 A 完成后统一验证。现有 Hub/NATS/PG/Scout 服务未停止或重启。
