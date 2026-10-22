# Sentinel

Sentinel 是具备 AI 能力的主机安全引擎，采用 Rust Cargo workspace，包含两个程序：

- **Hub**：服务端。托管 PostgreSQL 持久化、NATS JetStream 消息接入、管理 UI 与 API，负责集中管理与协调。
- **Scout**：主机 Agent。以宿主采集视图（特权容器或原生进程）运行在受管主机上，做只读资产采集（系统信息、CPU/内存、网络端口与速率、进程、软件包），经本地 SQLite 队列缓冲后上报。

## 当前状态（一期 A）

**已实现并通过测试：**

- Hub：SQLx 迁移（含 ledger 可重启幂等）、事件接收与幂等、授权 API、Vue 3 管理界面（资产列表/详情、分组、标签、能力页）、`/healthz` `/readyz` 健康端点、`hub migrate` 子命令、`SENTINEL_DATABASE_URL(_FILE)` 凭证文件支持（与直接 env 互斥）。
- Scout：持久 Ed25519 身份（`scout init`）、管理员登记（`scout enroll`）、常驻采集与断线补传（本地 SQLite 队列，1000 条 / 128 MiB 限额）、`scout once` / `scout status`（只读，常驻运行时可用）、运行时自检 `scout doctor`（只读 JSON：`detected_runtime` / `requested_mode` / `selected_mode` / `host_root` / `collection_allowed` 等；采集边界不满足时先输出 JSON 再以非零码退出）。
- 基础设施：GitHub Actions CI（PR/push 全量测试）、tag `v*` 发布工作流（多架构镜像 + cosign keyless 签名）、发布镜像一键安装脚本（下载/验证/运行分离）、原生发布包构建脚本 `scripts/build-native.py`（无容器运行时也可产包）、正式 systemd unit（`deploy/systemd/`）。均已通过本地静态检查（actionlint、shellcheck、gitleaks）与 mock 行为测试；本机已验证原生 Rust 构建与 PG/NATS 链路、原生进程的宿主采集视图。云端 CI 已在 GitHub 托管 runner 实际通过（run 39710748680，12 job 全绿）：镜像真实构建与容器内验收（入口/用户、无挂载 doctor 拒绝、静态资源、无凭证失败、真实 PG17 迁移），以及原生包与 Ubuntu 22.04/24.04 × amd64/arm64 四平台正式 unit 实际验收（启动/身份/队列/重启）；GHCR 推送与 OIDC 签名待首个 release。
- 测试：89 个 Rust 单元测试与 3 个 CLI 测试、PostgreSQL 应用集成测试、SQL 结构验证（47 表）、进程级端到端测试（含登记、队列补传、运行中 status 查询）、容器安装脚本 mock 行为测试，以及原生安装器 124 个回归用例；云端 CI 全量门禁（Rust/Web/SQL/e2e/scripts/images/native，run 39710748680）全部通过。

**尚未实现：**

- 漏洞评估、基线合规判定、恶意文件扫描、AI 分析、系统日志接入（Elasticsearch）。
- Scout 自动升级：升级能力计划由 Scout 内置实现，当前安装器仅支持全新安装；原生升级流程尚未实现，不能覆盖已有身份与队列。
- 跨主机部署边界：Hub 与 NATS 的 TLS、每主机独立 NATS 凭证/subject ACL 未实现（每主机的 Ed25519 安装身份已实现）；当前定位是单机/受控内网开发与验证环境（loopback，无 TLS）。
- 千台规模压测与正式安全评估未执行。

## 部署路线总览

| 路线 | 适用场景 | 前置 | 章节 |
| --- | --- | --- | --- |
| 开发 Compose（本机 loopback） | 开发与本机验证 | Docker + Compose | [docs/deployment.md 第 3 节](docs/deployment.md) |
| 签名 Docker Scout（`scripts/install-scout.sh`） | 已有容器运维体系的受管主机 | 首个 `v*` 发布 + Docker + cosign | [docs/deployment.md 第 4 节](docs/deployment.md) |
| 原生签名 Hub/Scout（`scripts/install-systemd.sh`） | 服务器/裸机 systemd 主机 | 首个 `v*` 发布 + systemd + cosign + 外部 PG/NATS | [docs/deployment.md 第 5 节](docs/deployment.md) |
| 本地自建包（`build-native.py` + `--local-bundle`） | 本机/未发布版本试用（**未签名，仅开发**） | Rust 工具链 + Node | [docs/deployment.md 第 5.5 节](docs/deployment.md) |

> 云端 CI 首轮全绿：run [39710748680](https://github.com/J1a-wei/Sentinel/actions/runs/39710748680) 12 个 job 全部 success，含镜像真实构建与四平台（Ubuntu 22.04/24.04 × amd64/arm64）正式 systemd unit 实际验收；CI 测试镜像的下载/校验/加载见 [docs/deployment.md 第 4.5 节](docs/deployment.md)，完整验证范围见其第 7 节。GHCR 正式发布与签名待首个 `v*` release。

## 快速开始

### 开发环境（本机 loopback）

```sh
# 1. 生成本机开发凭证（deploy/secrets/，0600，已 gitignore）
bash scripts/make-dev-secrets.sh

# 2. 准备 compose 环境变量
cp deploy/compose/.env.example deploy/compose/.env
# 编辑 .env：POSTGRES_PASSWORD 使用随机十六进制字符串；
# HUB_UID/HUB_GID 分别填写 id -u / id -g 输出的数字

# 3. 先启动 PostgreSQL / NATS / Hub（首次会构建镜像），等 Hub 就绪
#    注意：此时尚未启动 scout —— 未登记的常驻 Scout 会反复退出重启
#    并与后续 init 争用状态目录，应先完成 init/enroll 再启动
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml up -d --build --wait postgres nats hub

# 4. 初始化并登记开发 Scout（一次性，令牌来自 deploy/secrets/admin-token）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml run --rm --build scout init
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml run --rm \
  -v "$(pwd)/deploy/secrets/admin-token:/run/secrets/admin-token:ro" \
  -e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/admin-token \
  scout enroll

# 5. 启动常驻 Scout 并访问 Hub UI（管理员令牌登录）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml up -d --build scout
xdg-open http://127.0.0.1:8081
```

详细说明（含 Scout 状态查询、日志、清理、常见问题）见 [docs/deployment.md](docs/deployment.md)。

### 从发布镜像安装 Scout（容器主机）

> **注意：该方式依赖 GitHub Release 发布的签名镜像；首个 `v*` 版本发布前不可用。**

安装采用「下载审查 → 验证 → 运行」分离模式，脚本内置与发布工作流一致的
digest + 精确证书身份（`.../release.yml@refs/tags/<版本>`）+ issuer 验证，
验证失败立即退出，不会拉取或运行特权容器：

```sh
# 替换为实际已发布的 tag（需已存在，否则 404）
VERSION=v0.1.0

# 1. 下载（不直接执行），审查脚本内容
curl -fsSL \
  "https://raw.githubusercontent.com/J1a-wei/Sentinel/${VERSION}/scripts/install-scout.sh" \
  -o install-scout.sh
less install-scout.sh

# 2. 预览安装计划（离线，不执行任何操作）
bash install-scout.sh --version "${VERSION}" --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 --plan

# 3. 完整安装（验证签名 -> init -> enroll -> 启动特权容器）
# 生产/跨机环境的前置：Hub 与 NATS 必须已具备 TLS 终结与鉴权配置（本批未内置，
# 见 docs/deployment.md 的安全边界），NATS 地址形如 tls://nats.example.com:4222
sudo bash install-scout.sh --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 \
  --nats-token-file nats.token --enroll-token-file enroll.token
```

`--dry-run`（只读验证+预览）、`--verify-only`（验证后退出）、`--fetch-only`
（验证+拉取不运行）供分阶段审查。全部选项见脚本 `--help` 与
[docs/deployment.md](docs/deployment.md)。

### 原生二进制 + systemd 安装 Hub / Scout（服务器/裸机）

> **注意：该方式依赖 GitHub Release 发布的签名原生包；首个 `v*` 版本发布前不可用。**
> Hub 需要外部已就绪的 PostgreSQL 与 NATS（安装器只做连通性预检，**不会安装或配置数据库/消息系统**）。

```sh
VERSION=v0.1.0   # 替换为实际已发布的 tag

# 下载安装器（不直接执行），审查内容
curl -fsSL \
  "https://raw.githubusercontent.com/J1a-wei/Sentinel/${VERSION}/scripts/install-systemd.sh" \
  -o install-systemd.sh
less install-systemd.sh

# 离线预览安装计划（不联网、不检查工具、不写任何状态）
bash install-systemd.sh --component scout --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 --plan

# 完整安装 Scout（验证签名包 -> doctor 自检 -> init -> enroll -> 安装 unit 并启动）
sudo bash install-systemd.sh --component scout --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 \
  --nats-token-file nats.token --enroll-token-file enroll.token

# 完整安装 Hub（外部 PG/NATS 已就绪；以专用非特权用户 sentinel-hub 运行）
sudo bash install-systemd.sh --component hub --version "${VERSION}" \
  --database-url-file database-url --admin-token-file admin.token \
  --nats-url nats://nats.example.com:4222 --bind 127.0.0.1:8080
```

安装后用 systemd 管理：`systemctl status sentinel-scout`、
`journalctl -u sentinel-scout -f`；详细选项、固定路径契约、凭证与
`scout doctor` 采集边界说明见 [docs/deployment.md 第 5 节](docs/deployment.md)。

### 本地自建包试用（未签名，仅本机开发）

在未发布任何 `v*` 版本时，可在本机构建与安装器契约一致的本地包：

```sh
# 构建本地包（默认执行 cargo release 构建与 web 前端构建）
python3 scripts/build-native.py --version v0.1.0-local --output-dir dist
# 产物：dist/sentinel-v0.1.0-local-linux-<amd64|arm64>.tar.gz（未签名）

# 用安装器以本地包安装（显式声明本地未签名模式，不执行发布链路验签）
sudo bash scripts/install-systemd.sh --component scout \
  --local-bundle dist/sentinel-v0.1.0-local-linux-amd64.tar.gz \
  --version v0.1.0-local \
  --hub-url http://127.0.0.1:8081 --nats-url nats://127.0.0.1:14222 \
  --nats-token-file deploy/secrets/nats-client-token \
  --enroll-token-file deploy/secrets/admin-token
```

`--local-bundle` 模式会在输出中明确声明「本地未发布/未签名」，不得视为正式发布链路验证。

## 仓库结构

```
crates/hub       Hub 服务端（Axum + SQLx + async-nats）
crates/scout     Scout Agent（采集 + SQLite 队列 + 补传）
crates/protocol  共享协议类型
web/             Vue 3 + TypeScript + Vite 管理界面
migrations/      PostgreSQL 迁移（SQLx 编译期内嵌）
deploy/          开发 compose 编排；systemd 正式 unit（随原生包分发）
scripts/         安装脚本（容器/原生 systemd）、本地包构建、开发凭证生成、脚本测试
.github/         CI（测试）与 Release（构建/签名/发布）工作流
Dockerfile       多阶段构建：hub / scout 两个 target
```

## 文档

- [docs/architecture.md](docs/architecture.md)：架构与技术选型
- [docs/requirements.md](docs/requirements.md)：功能范围与阶段规划
- [docs/implementation-contract.md](docs/implementation-contract.md)：接口、环境变量与行为契约
- [docs/database.md](docs/database.md)：数据模型
- [docs/deployment.md](docs/deployment.md)：部署指南（四条路线、安全边界、验证状态）
- [docs/local-testing.md](docs/local-testing.md)：本机采集、故障恢复与浏览器验收记录

## 开发检查

```sh
cargo fmt --all -- --check
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

推送与 PR 由 GitHub Actions 自动执行上述检查、前端构建、SQL 验证、端到端
冒烟与镜像构建（见 `.github/workflows/ci.yml`）；`v*` tag 触发发布工作流。

## 许可证

尚未确定。许可证选择确定前，本仓库不附带任何许可证声明。
