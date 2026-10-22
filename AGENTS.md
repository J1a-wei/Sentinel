# Sentinel 开发指南

## 项目定位

Sentinel 是具备 AI 能力的主机安全引擎，Hub 与 Scout 统一使用 Rust，采用一个 Cargo workspace：

- **Hub**：服务端，负责集中管理和协调。
- **Scout**：Agent 端，负责主机监控、威胁检测和防护。

当前正在实施一期 A：主机资产、只读采集、可靠上报和管理界面。实际交付范围以 [实现接口约定](docs/implementation-contract.md) 和测试结果为准；设计文档中的后续能力不能视为已经实现。

## 目录职责

- `Cargo.toml`：workspace 成员、共享依赖与构建配置。
- `Cargo.lock`：应用依赖锁文件。
- `rust-toolchain.toml`：固定工具链与开发组件。
- `crates/hub`：Hub 可执行程序及内部模块。
- `crates/scout`：Scout 可执行程序及内部模块。
- `crates/protocol`：Hub 与 Scout 共用的有版本消息和签名协议，不引入数据库或 Web 服务依赖。
- `web`：Vue 3、TypeScript 与 Vite 管理界面，调用真实 Hub API。
- `migrations`：SQLx 版本迁移；已有迁移投入使用后通过新迁移演进，不原地改写。
- `configs`：可提交的配置示例，不存放真实凭证。
- `deploy`、`scripts`：部署配置、可审查的安装与验证脚本。
- `deploy/systemd`：原生 Hub/Scout 服务单元；`scripts/build-native.py` 构建原生发行包。
- `.github/workflows`：检查、镜像构建、发布与签名工作流。
- `docs`：架构、设计和使用文档。

各 crate 的 `src/main.rs` 保持精简，业务逻辑放在相应 crate 的内部模块中。AI 模块随实际调用方引入；仅在出现实际复用需求时抽取共享 crate。避免让 Scout 依赖 Hub 的数据库、Web 或日志检索实现。

架构与选型状态见 [docs/architecture.md](docs/architecture.md)，功能范围见 [docs/requirements.md](docs/requirements.md)，数据模型见 [docs/database.md](docs/database.md)。依赖和工具链以提交的清单及锁文件为准。

## 开发约定

- 使用 Rust 1.97.1、edition 2024；最低支持版本记录于 Cargo 配置，具体工具链由 `rust-toolchain.toml` 固定。升级工具链需同步检查 CI 与镜像构建。
- 遵循 Rust 常用命名和模块组织方式，使用 rustfmt 和 Clippy；应用 workspace 提交 `Cargo.lock`。
- 显式处理 `Result`，保留错误来源和必要上下文；业务输入、网络及文件操作的可预期错误不得依赖 `unwrap`、`expect` 或 panic 处理。
- 为 I/O、外部进程和后台任务设计超时、取消及退出清理；阻塞或 CPU 密集工作使用有并发上限的执行机制，避免阻塞异步运行时。
- 优先使用安全 Rust；确需 `unsafe` 或 FFI 时保持范围最小，说明并验证安全不变量。语言安全不能替代权限、输入和资源边界验证。
- 涉及外部输入时验证输入；日志中不记录凭证或敏感主机数据。
- 不提交真实密钥、令牌、密码、生产配置或采集到的敏感数据。
- 新增或变更业务行为时，编写覆盖相关成功与失败场景的测试。
- 修改尽量聚焦于当前任务。PostgreSQL、NATS JetStream 和 Elasticsearch 已在架构中确定，但仅在相应功能实际实施时引入客户端依赖；AI SDK 和其他依赖同样按需求引入。

## 数据库规范

每张业务表必须包含以下四个字段，关联表、当前状态表、明细表、历史表和指标表也不得省略：

```sql
id uuid PRIMARY KEY,
create_time timestamptz NOT NULL DEFAULT now(),
update_time timestamptz NOT NULL DEFAULT now(),
"delete" boolean NOT NULL DEFAULT false
```

- `id` 是唯一的主键列，由 Rust 应用生成；不得用业务字段或复合主键替代。原业务唯一性使用独立 `UNIQUE` 约束或合适的唯一索引保留，跨资产外键和消息幂等约束不得弱化。
- `create_time` 表示记录创建时间，创建后不可修改；`update_time` 表示记录最近一次数据库更新的时间。统一挂载 `sentinel.set_row_metadata()` 的 `BEFORE UPDATE` 行触发器，冻结 `id`/`create_time` 并维护 `update_time`，包括软删除。不能仅声明默认值而不维护更新。
- 通用时间列只使用上述名称；采集、接收、发布和执行等业务时间单独保留，不能被通用时间列替代，也不能用 `update_time` 判断消息新旧或业务完成顺序。
- `delete` 表示软删除：`false` 为正常记录，`true` 为已删除。SQL 中统一写成双引号形式 `"delete"`。默认查询、统计、授权与调度显式过滤 `NOT "delete"`；关联查询也检查被关联对象，外键本身不验证软删除状态。
- 可重新建立的绑定/标签按未删除记录建立唯一索引。身份、版本、快照、任务、消息与证据等不可重复的业务键跨软删除继续保留；不得用软删除释放执行互斥或绕开幂等。
- 软删除不替代吊销、退役、取消、修复等业务状态迁移。审计、修订与证据仍遵守追加/正文不可变及保留要求，通用字段不授予修改历史的权限。
- 普通业务删除使用软删除；到期物理清理由受控保留任务完成，先检查关联、证据和聚合依赖，不做隐式级联删除。
- 所有表必须满足 `id` 单列主键。当前指标使用普通表、业务唯一键和时间索引；未经规范调整，不引入与此要求冲突的时间分区设计。
- 变更表结构后验证全表四字段、主键、触发器和原业务约束，并覆盖更新时间、软删除、重复数据与跨资产引用的成功/失败场景。

## 开发检查

Rust 工作区使用：

```sh
cargo fmt --all -- --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

前端使用 `npm --prefix web ci` 和 `npm --prefix web run build`，并运行与变更相关的前端测试。数据库变更在 PostgreSQL 17+ 验证迁移及 `docs/sql/verify.sql`；安装与发布变更验证失败路径，确保签名校验失败时不会启动镜像。

原生部署变更还需运行安装脚本测试、`systemd-analyze verify` 和 `tests/native_smoke.py`，覆盖运行环境识别、只读诊断和持久身份。正式原生包在 Ubuntu 22.04 构建，检查 ELF 架构及 glibc 基线，并在 Ubuntu 22.04/24.04 的 amd64/arm64 上验证；本机未覆盖的平台明确交由 CI 验证，不将配置了检查等同于检查通过。

Rust 代码变更提交前运行以上检查。仅文档变更检查链接、选型及实现状态的一致性；如缺少工具链、外部服务或环境条件导致无法验证，明确说明，不声称构建或测试通过。

## 发布与安装

- Hub 与 Scout 发布镜像通过 Cosign 签名，按 digest 分发和运行。签名使用 GitHub Actions OIDC 身份，验证固定发布仓库、工作流和标签身份及 OIDC issuer。
- PR 检查不授予发布或签名权限；发布任务在检查通过后执行。签名或校验失败必须终止，不提供静默跳过校验的安装路径。
- 安装脚本只在验证镜像身份和摘要后启动容器；不在日志、命令行参数或仓库中保存真实凭证。
- 本地开发构建与正式签名发布分别说明；没有成功发布的镜像不能被描述为可下载的安装版本。
- 原生归档使用 Cosign `sign-blob` 签名并附 Sigstore bundle，安装前通过 `verify-blob` 固定相同的发布工作流、标签与 issuer；验证整个归档后才能解包或执行。显式本地构建模式与正式发布验证分开说明。
- 原生 systemd 安装保留持久身份与队列，常驻 Scout 不保留登记用管理员凭证。自动运行环境识别不确定时要求显式配置；容器宿主挂载缺失时不得回退到容器自身根。

## 协作说明

`AGENTS.md` 是协作规范的唯一来源。`CLAUDE.md` 是指向本文件的相对软链接，请保留该链接并在本文件中更新规范。
