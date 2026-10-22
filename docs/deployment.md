# Sentinel 部署指南

本文覆盖四条部署路线：开发环境（本机 loopback compose）、发布镜像安装 Scout（一键脚本）、原生二进制 + systemd 安装 Hub/Scout、本地自建包试用；另附 Hub 服务器侧容器部署参考。

## 1. 定位与安全边界（务必先读）

Sentinel 当前处于**一期 A**：只读资产采集与上报。

| 边界 | 状态 |
| --- | --- |
| 每主机 Ed25519 安装身份、登记授权、消息幂等 | 已实现 |
| 跨机部署的 Hub/NATS TLS 终结与外置鉴权 | **未实现**，需部署方自行在边界提供（反向代理、NATS TLS 配置） |
| 每主机独立 NATS 凭证 / subject ACL | **未实现**（当前共享一个传输 token） |
| Scout 自动升级 | **未实现**，升级能力由 Scout 后续内置实现；当前需人工重装 |
| 千台规模压测、正式安全评估 | **未执行** |

因此：**当前面向单机与受控内网开发/验证环境**（loopback、无 TLS）。生产拓扑（多主机、公网暴露）在本批不提供完整保障，安装脚本中的 `--hub-url https://...`、`--nats-url tls://...` 仅表示地址格式，实际 TLS 与鉴权须由部署方预先配置。

## 2. 部署路线总览

| 路线 | 安装物 | 前置 | 适用 |
| --- | --- | --- | --- |
| 开发 Compose | 源码构建镜像 | Docker + Compose | 开发、本机验证（第 3 节） |
| 签名 Docker Scout | `ghcr.io` 多架构镜像（cosign keyless） | 首个 `v*` 发布 + Docker + cosign 3.x | 已有容器运维体系的受管主机（第 4 节） |
| 原生签名 Hub/Scout | `sentinel-vX.Y.Z-linux-{amd64,arm64}.tar.gz`（cosign 签名 bundle） | 首个 `v*` 发布 + systemd + cosign 3.x + 外部 PG/NATS | 服务器/裸机 systemd 主机（第 5 节） |
| 本地自建包 | `build-native.py` 产出的未签名本地包 | Rust 工具链 + Node | 本机/未发布版本试用，**显式未签名仅开发**（第 5.5 节） |

原生路线与容器路线共用同一发布工作流签名身份（`.../release.yml@refs/tags/<版本>`），但验证方式不同：

- **镜像**：`cosign verify --certificate-identity ... --certificate-oidc-issuer ... 镜像@digest`（registry 内按 digest 验证，见第 4 节）。
- **原生包**：`cosign verify-blob --bundle <包>.tar.gz.sigstore.json ... <包>.tar.gz`（对 blob 与旁车 sigstore bundle 验证，默认执行 tlog 校验，见第 5.2 节）。

## 3. 开发环境部署（本机 loopback）

端口规划（仅绑定 127.0.0.1，均可经 `deploy/compose/.env` 覆盖）：

| 服务 | 端口 | 说明 |
| --- | --- | --- |
| Hub UI/API | 127.0.0.1:8081 -> 8080 | 管理界面与 API |
| PostgreSQL 17 | 127.0.0.1:5440 -> 5432 | 持久卷 `pgdata` |
| NATS 2.15.1 | 127.0.0.1:14222 -> 4222 | JetStream 文件存储，持久卷 `natsdata` |
| NATS 监控 | 127.0.0.1:18222 -> 8222 | `/healthz` 等只读监控端点 |

### 3.1 步骤

```sh
# 1. 生成本机开发凭证（deploy/secrets/，0600，目录已 gitignore）
bash scripts/make-dev-secrets.sh

# 2. 准备 compose 环境变量
cp deploy/compose/.env.example deploy/compose/.env
# 编辑：POSTGRES_PASSWORD 使用随机十六进制字符串；
# HUB_UID/HUB_GID 分别填写 id -u / id -g 输出的数字
#（hub 容器以该 UID/GID 运行，须与 deploy/secrets/ 文件属主一致）

# 3. 先启动 postgres nats hub（首次构建镜像），等 Hub 健康检查通过
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml up -d --build --wait postgres nats hub

# 4. 一次性初始化并登记开发 Scout（令牌来自 deploy/secrets/admin-token）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml run --rm --build scout init
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml run --rm \
  -v "$(pwd)/deploy/secrets/admin-token:/run/secrets/admin-token:ro" \
  -e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/admin-token \
  scout enroll

# 5. 最后启动常驻 Scout（状态目录为仓库 var/scout，已 gitignore）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml up -d --build scout
```

> **顺序要求**：先 `postgres nats hub` 再 init/enroll，最后才启动 `scout`。
> 未登记的常驻 Scout 会立即退出并陷入重启循环，且与 init 争用状态目录锁。

浏览器打开 `http://127.0.0.1:8081`，用 `deploy/secrets/admin-token` 的内容登录。

### 3.2 常用操作

```sh
# Scout 只读状态（常驻运行时可用，不取写锁）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml exec scout scout status

# 日志
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml logs -f scout

# 全部停止并清除数据卷（含 PG/NATS 数据与 Scout 身份，不可逆）
docker compose --project-directory deploy/compose \
  -f deploy/compose/docker-compose.dev.yml down -v
rm -rf var/scout
```

### 3.3 开发环境凭证说明

- `scripts/make-dev-secrets.sh` 生成三个 0600 文件：`admin-token`（Hub 管理令牌）、`nats-client-token`（NATS token）、`nats-server.conf`（NATS 服务端配置，token 内嵌，避免出现在容器 argv）。
- NATS token 不写入 compose 的 `command:`，配置文件以只读挂载，`docker inspect` 与进程 argv 均不含凭证。
- hub 为非特权容器（镜像内 `USER sentinel`），compose 用 `user: "${HUB_UID}:${HUB_GID}"` 与宿主创建 secrets 的 UID/GID 对齐，否则非特权用户读不到 0600 凭证文件会启动失败。
- `--force` 重新生成仅轮换管理/NATS 凭证，不会作废 `var/scout` 中已登记的 Ed25519 身份；轮换后需重启 NATS、Hub 与 Scout，使各进程重新读取凭证文件。

## 4. 发布镜像安装 Scout（受管主机）

### 4.1 前置条件

1. **首个 `v*` 版本已发布**：镜像来自 GitHub Release 工作流（多架构 linux/amd64、linux/arm64，cosign keyless 签名）。
2. **GHCR 包可见性**：首次推送的 package 默认 private。仓库公开后仍需在 GitHub 上核对 `sentinel-hub`、`sentinel-scout` 两个包的可见性为 **public**，他人才能匿名拉取与验证（见官方文档：
   <https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry>）。
3. 主机已安装 Docker Engine（含 buildx 插件）、cosign **3.x**（与发布工作流固定的 v3.0.6 一致；v2 对本批签名格式未验证）、python3。
4. 已从 Hub 管理员处获得 `enroll.token`（登记令牌）；若 NATS 启用了传输认证，另需 `nats.token`。
5. 生产/跨机环境须已具备 TLS 与鉴权边界（反向代理终结 Hub 的 TLS、NATS TLS 配置等），见第 1 节。

### 4.2 下载、审查、安装（分离执行）

```sh
VERSION=v0.1.0   # 替换为实际已发布的 tag

# 1. 下载脚本（不直接执行），审查内容
curl -fsSL \
  "https://raw.githubusercontent.com/J1a-wei/Sentinel/${VERSION}/scripts/install-scout.sh" \
  -o install-scout.sh
less install-scout.sh

# 2. 离线预览安装计划（不联网、不检查 docker/cosign、不写任何状态）
bash install-scout.sh --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 --plan

# 3. 完整安装
sudo bash install-scout.sh --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 \
  --nats-token-file nats.token --enroll-token-file enroll.token
```

### 4.3 脚本的安全行为

- **验证先于一切**：解析 tag 的 manifest index digest（解析后固定引用，实际拉取与运行全部使用 `镜像@digest`）→ 校验 manifest 含当前主机平台 → cosign 严格验证。identity/issuer 为精确值，不允许任意正则，不关闭 tlog 校验：

  ```sh
  cosign verify \
    --certificate-identity "https://github.com/J1a-wei/Sentinel/.github/workflows/release.yml@refs/tags/v0.1.0" \
    --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
    "ghcr.io/j1a-wei/sentinel-scout@sha256:..."
  ```

  任何一步失败立即退出，**不会执行 `docker pull` / `docker run`**（mock 测试已覆盖该行为）。
- **凭证不落 argv/日志**：登记令牌与 NATS token 只通过 0600 文件挂载（`SENTINEL_ADMIN_TOKEN_FILE` / `SENTINEL_NATS_TOKEN_FILE`）；URL 校验拒绝 userinfo（`user:pass@host`），避免凭证进入命令行、env 文件或日志。
- **不覆盖、不升级**：已存在同名容器或非空状态目录时拒绝安装；升级由 Scout 后续内置功能承担，脚本不提供。
- **启动后确认**：启动 `--privileged --network host --pid host` 容器（只读挂载 `/proc` `/sys` `/etc` `/usr/lib/os-release` `/var/lib/dpkg` 到 `/host`；`/etc/os-release` 常为符号链接，故显式挂载 `/usr/lib/os-release`），并验证容器未退出；未登记/配置错误的 Scout 会立即退出，脚本不会假报成功。
- **全新安装必须提供 `--enroll-token-file`**；已登记主机重建容器用 `--resume`（可省略令牌，跳过 `init`，不声称重新登记）。

### 4.4 模式与常用选项

| 参数 | 作用 |
| --- | --- |
| `--plan` | 离线预览，不联网不检查工具 |
| `--dry-run` | 完整验证（digest/平台/签名）+ 打印计划，零写入 |
| `--verify-only` | 验证后退出，不拉取不运行 |
| `--fetch-only` | 验证并拉取，不运行（供审查镜像） |
| `--resume` | 状态目录非空但容器不存在时续装（跳过 init） |
| `--state-dir` / `--config-dir` | 默认 `/var/lib/sentinel` / `/etc/sentinel`（需 root） |
| `--container-name` / `--image` | 默认 `sentinel-scout` / `ghcr.io/j1a-wei/sentinel-scout`（`--image` 主要供测试） |
| `--asset-name` / `--group-id` / `--interval` | 登记显示名 / 分组 / 采集间隔（5..3600 秒） |

安装完成后：

```sh
docker logs -f sentinel-scout            # 日志（登记/上报情况）
docker exec sentinel-scout scout status  # 只读状态，常驻运行时可用
```

## 5. 原生二进制 + systemd 部署（Hub / Scout）

> **前置声明**：签名包路线依赖 GitHub Release 发布的 `sentinel-vX.Y.Z-linux-{amd64,arm64}.tar.gz` 与旁车 `.tar.gz.sigstore.json`；**首个 `v*` 版本发布前该路线不可用**（无公开产物可下载），期间请使用第 5.5 节本地自建包路线。

### 5.1 前置条件

1. 主机：Ubuntu 22.04 / 24.04（amd64 或 arm64），systemd 作为 init（`systemd-detect-virt` 判定非容器环境；容器主机请改用第 4 节 Docker 路线）。安装与 unit 依赖 `Type=exec`、`StateDirectory`，需 systemd ≥ 240（Ubuntu 22.04 为 249，已满足）。
2. 工具：cosign **3.x**、python3；下载脚本的示例使用 curl；安装需 root（sudo）。
3. **外部依赖已就绪**：Hub 需要可访问的 PostgreSQL 与 NATS（含凭证文件）；安装器只做连通性/迁移预检，**不安装、不配置数据库或消息系统**。跨机环境的 TLS 与鉴权边界见第 1 节。
4. Scout 全新安装需 `--enroll-token-file`（管理员登记令牌）；Hub 需 `--database-url-file` 与 `--admin-token-file`（均 0600；源文件不会被删除）。

### 5.2 安装包与签名验证

发布包为 tar.gz 归档（无顶层目录），根级布局：

```
bin/hub bin/scout web/dist/** deploy/systemd/sentinel-{hub,scout}.service VERSION ARCH
```

签名验证为 `cosign verify-blob`（对 blob + 旁车 sigstore bundle），identity/issuer 为精确值、不关闭 tlog 校验：

```sh
cosign verify-blob \
  --bundle "sentinel-v0.1.0-linux-amd64.tar.gz.sigstore.json" \
  --certificate-identity "https://github.com/J1a-wei/Sentinel/.github/workflows/release.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "sentinel-v0.1.0-linux-amd64.tar.gz"
```

与第 4 节镜像验证（`cosign verify` 按 registry digest）不同：这里验证的是**归档文件字节**本身，签名者身份相同（同一发布工作流、同一 tag ref）。任何一步失败安装器立即退出，不解包、不执行包内任何文件。

安装器为每次 Cosign 验证创建独立的 `0700` TUF 缓存目录，显式传入 `TUF_ROOT`，不继承调用者的 HOME、缓存或信任覆盖变量；该临时目录随本次操作清理。

### 5.3 安装 Scout

```sh
VERSION=v0.1.0   # 替换为实际已发布的 tag

# 下载安装器（不直接执行），审查内容
curl -fsSL \
  "https://raw.githubusercontent.com/J1a-wei/Sentinel/${VERSION}/scripts/install-systemd.sh" \
  -o install-systemd.sh
less install-systemd.sh

# 离线预览（不联网、不检查工具、不写状态）
bash install-systemd.sh --component scout --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 --plan

# 完整安装（验证签名包 -> scout doctor 自检 -> init -> enroll ->
#           安装 unit -> enable+start -> 确认服务运行）
sudo bash install-systemd.sh --component scout --version "${VERSION}" \
  --hub-url https://hub.example.com --nats-url tls://nats.example.com:4222 \
  --nats-token-file nats.token --enroll-token-file enroll.token
```

**doctor 采集边界自检**：安装器在登记与启用服务前运行只读的 `scout doctor`，并要求 JSON 结果中 `selected_mode == "native"` 且 `collection_allowed == true`；检测为 unknown/容器时拒绝继续（不会启用一个无法采集的服务）。unit 本身也带 `ExecStartPre=... scout doctor`，每次启动前自检，失败则拒绝启动。若 doctor 无法自动判定（如 cgroup 信息不足）而管理员已人工核实为原生主机，可用 `--runtime-mode native` 显式声明（仅接受 `native|auto`，默认 `auto`，安装器不会悄悄改写判定）。

**常驻 Scout 不携带管理员凭证**：`enroll` 只在安装过程中以临时副本（0600，用后删除）注入 `SENTINEL_ADMIN_TOKEN_FILE`，登记幂等可重试；常驻 unit 的 env 文件中不含任何管理员令牌。

### 5.4 安装 Hub

```sh
sudo bash install-systemd.sh --component hub --version "${VERSION}" \
  --database-url-file database-url \
  --admin-token-file admin.token \
  --nats-url nats://nats.example.com:4222 \
  --bind 127.0.0.1:8080
```

- 以专用系统用户/组 `sentinel-hub` 非特权运行（安装器创建）；`--bind` 默认 `127.0.0.1:8080`，公网访问须经反向代理提供 TLS 与访问控制（见第 1 节）。
- 凭证经 `SENTINEL_DATABASE_URL_FILE` / `SENTINEL_ADMIN_TOKEN_FILE` / `SENTINEL_NATS_TOKEN_FILE` 文件注入（0600），与直接 env 形式互斥；命令行 Hub/NATS URL 不含 userinfo，数据库密码仅写入私有数据库 URL 文件。
- 安装器在启用服务前以 `sentinel-hub` 用户执行一次 `hub migrate`（连接外部 PostgreSQL 并应用迁移）做失败归因预检；服务启动时迁移幂等重放，NATS 连接由 Hub 内部重试；安装器等待 `/readyz` 成功后才报告安装完成。
- 安装前检查 `--bind` 地址可独占绑定。启动后除 `/readyz` 外，还用本次管理员凭证检查 session，并复核同一 systemd MainPID 持续运行、重启次数为零，防止将已有 Hub 的就绪响应误判为新服务安装成功。

### 5.5 本地自建包试用（未签名，仅本机开发）

```sh
# 构建本地包（默认 cargo release 构建 + web 前端构建；需 Rust 工具链与 Node）
python3 scripts/build-native.py --version v0.1.0-local --output-dir dist
# 产物：dist/sentinel-v0.1.0-local-linux-<amd64|arm64>.tar.gz（未签名本地包）

# 以本地包安装（--version 必须与包内 VERSION 一致）
sudo bash scripts/install-systemd.sh --component scout \
  --local-bundle dist/sentinel-v0.1.0-local-linux-amd64.tar.gz \
  --version v0.1.0-local \
  --hub-url http://127.0.0.1:8081 --nats-url nats://127.0.0.1:14222 \
  --nats-token-file deploy/secrets/nats-client-token \
  --enroll-token-file deploy/secrets/admin-token
```

`--local-bundle` 是显式的「本地未发布/未签名模式」：安装器会明确声明未执行发布链路验签，其产物**不得视为经过签名验证的正式发布物**。开发加速可用
`python3 scripts/build-native.py --skip-build --binary-dir target/debug --web-dir web/dist ...` 直接打包已构建产物。

### 5.6 固定路径与安装边界

安装路径与 root 仓库 `deploy/systemd/` 正式 unit 完全一致（两组件目录相互独立，可同机共存）：

| 项 | Hub | Scout |
| --- | --- | --- |
| 二进制 | `/opt/sentinel/hub/bin/hub` | `/opt/sentinel/scout/bin/scout` |
| Web 资产 | `/opt/sentinel/hub/web/dist` | — |
| env 文件 | `/etc/sentinel/hub/hub.env` | `/etc/sentinel/scout/scout.env` |
| 状态目录 | `/var/lib/sentinel-hub`（StateDirectory，0700） | `/var/lib/sentinel-scout`（StateDirectory，0700） |
| unit | `/etc/systemd/system/sentinel-hub.service` | `/etc/systemd/system/sentinel-scout.service` |
| 运行用户 | `sentinel-hub`（安装器创建的系统用户） | `root`（宿主 proc/sys 只读采集视图所需） |

- **仅全新安装**：已存在组件安装目录、配置目录、状态目录（包括空目录）、unit 或 Hub 专用账号时拒绝安装；不做覆盖、不做升级、不提供 resume——失败时保留已写入的凭证与状态（不破坏 Ed25519 身份），人工排查时保留原身份和队列；原生升级与续装流程尚未实现，不应删除状态来绕过保护。
- **失败处理**：验签、doctor、init、enroll、迁移失败时不会 enable/start 服务；若启动后未通过就绪检查，安装器会停止并取消启用本次新服务，同时保留身份和队列供排查。
- Scout unit 保留宿主 PID/网络视图（不启用 PrivateNetwork/ProtectProc 等会遮蔽采集的隔离），能力面收敛到只读采集所需（`CAP_DAC_READ_SEARCH`、`CAP_SYS_PTRACE`）；Hub unit 采用非特权 + 只读根文件系统的常规硬化。
- Scout 的 `SENTINEL_HOST_ROOT` 默认不设置（native 模式即 `/`）；容器路线才使用 `/host`。

### 5.7 安装后运维

```sh
systemctl status sentinel-scout          # 运行状态（Hub 同理 sentinel-hub）
systemctl is-active sentinel-scout       # 脚本安装完成判定使用同一命令
journalctl -u sentinel-scout -f          # 常驻日志（含 doctor 自检、采集、上报情况）
sudo systemctl stop sentinel-scout       # 停止（SIGTERM 优雅退出）
sudo systemctl disable --now sentinel-scout  # 停止并取消开机自启

# Scout 只读状态（常驻运行时可用，不取写锁）
sudo env SENTINEL_STATE_DIR=/var/lib/sentinel-scout \
  /opt/sentinel/scout/bin/scout status
```

### 5.8 模式与常用选项

| 参数 | 作用 |
| --- | --- |
| `--component hub\|scout` | 组件选择（必选） |
| `--version vX.Y.Z` | 发布版本，须与包内 `VERSION` 一致（必选） |
| `--plan` | 离线预览，不联网不检查工具 |
| `--dry-run` | 下载 + 验签 + 归档布局校验 + 打印计划；仅用临时目录，不解包执行或安装 |
| `--verify-only` | 完整验证后退出，不安装 |
| `--fetch-only --output-dir dist` | 下载已验证包（含 bundle）到指定目录，不安装，供审查分发 |
| `--local-bundle FILE` | 本地未签名包模式（显式声明，不走发布链路验签） |
| `--hub-url` / `--nats-url` | Hub/NATS 地址（Scout 必填；URL 拒绝 userinfo） |
| `--enroll-token-file` | 登记令牌 0600 文件（Scout 全新安装必填，用后删除副本） |
| `--database-url-file` / `--admin-token-file` | Hub 必填凭证文件（0600；token ≥32 字符） |
| `--nats-token-file` | NATS 传输 token 0600 文件（可选） |
| `--bind` | Hub 监听地址，默认 `127.0.0.1:8080` |
| `--runtime-mode auto\|native` | Scout 运行时模式显式声明，默认 `auto`（不悄悄覆盖自动判定） |
| `--interval` / `--asset-name` / `--group-id` | 采集间隔（5..3600 秒）/ 登记显示名 / 分组 |

## 6. Hub 服务器侧部署参考（容器）

镜像：`ghcr.io/j1a-wei/sentinel-hub@sha256:...`（release 页提供精确 digest 与验证命令）。
先复制对应发布的完整镜像摘要并验证，成功后再执行下方容器命令：

```sh
VERSION=v0.1.0   # 替换为实际已发布的 tag
HUB_IMAGE='ghcr.io/j1a-wei/sentinel-hub@sha256:<替换为该发布的完整摘要>'
cosign verify \
  --certificate-identity "https://github.com/J1a-wei/Sentinel/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "${HUB_IMAGE}"
```

systemd 主机也可直接使用第 5.4 节原生安装路线；下例为容器方式。

启动时自动执行 SQLx 迁移；DBA 可先显式执行一次性迁移（`SENTINEL_DATABASE_URL_FILE` 与直接 env 形式互斥，二者只能提供其一）：

```sh
# 凭证文件 0600，属主与容器运行用户一致（镜像内用户为非特权 sentinel）
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -e SENTINEL_DATABASE_URL_FILE=/run/secrets/sentinel-database-url \
  -e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/admin-token \
  -v "$PWD/secrets/sentinel-database-url:/run/secrets/sentinel-database-url:ro" \
  -v "$PWD/secrets/admin-token:/run/secrets/admin-token:ro" \
  "${HUB_IMAGE}" migrate
```

常驻运行（端口只映射 loopback，公网访问须经反向代理提供 TLS 与访问控制）：

```sh
docker run -d --name sentinel-hub \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8081:8080 \
  -e SENTINEL_DATABASE_URL_FILE=/run/secrets/sentinel-database-url \
  -e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/admin-token \
  -e SENTINEL_NATS_URL=tls://nats.example.com:4222 \
  -e SENTINEL_NATS_TOKEN_FILE=/run/secrets/nats-token \
  -v "$PWD/secrets/sentinel-database-url:/run/secrets/sentinel-database-url:ro" \
  -v "$PWD/secrets/admin-token:/run/secrets/admin-token:ro" \
  -v "$PWD/secrets/nats-token:/run/secrets/nats-token:ro" \
  --restart unless-stopped \
  "${HUB_IMAGE}"
```

- `SENTINEL_ADMIN_TOKEN(_FILE)` 必填且 ≥32 字符；`SENTINEL_DATABASE_URL(_FILE)` 同样支持文件形式（trim 尾部换行，上限 16 KiB），与直接变量互斥。
- NATS 服务端建议同样以配置文件方式启用 token/TLS（参考 `scripts/make-dev-secrets.sh` 生成的 `nats-server.conf` 结构），不要把 token 放进命令行参数。
- 健康检查：镜像内置 `hub health`（对运行中实例的 `/readyz` 发起探测）；外部编排可探测 `/healthz` `/readyz`。

## 7. 已验证与未验证事项

**已验证（本机，开发定位）：**

- 原生 Rust 构建（cargo build/test/clippy --locked）、89 个单元测试与 3 个 CLI 测试、PG 应用集成测试、SQL 结构验证。
- 进程级端到端链路（init → enroll → once → JetStream → PostgreSQL → API，含断线补传与运行中只读 status）；原生进程的宿主采集视图（`scout doctor` 在真实主机返回 `native` / `collection_allowed=true`）。
- 容器安装脚本：actionlint、shellcheck、gitleaks 静态检查 + 110 项 mock 行为断言（验证失败不运行 Docker、dry-run 零写入、凭证不泄漏等）。
- compose 编排配置校验（`docker compose config`）。
- 正式 systemd unit（`deploy/systemd/`）语法在 systemd 249 上通过校验；本地可产出契约一致的未签名原生包（`scripts/build-native.py`）。
- 原生安装器：124 个回归用例通过，包括验签失败不解包执行、独立私有 TUF 缓存、目录/凭证权限、已有安装拒绝、Hub 就绪归属检查，以及登记/启动失败后的清理和状态保留。实际本地包的 `verify-only`、`dry-run`、`fetch-only` 通过；安装用例模拟系统边界，没有安装本机服务。

**未验证（诚实声明）：**

- Docker 镜像**实际构建**：本机 Docker 守护进程无权限，`Dockerfile` 仅经静态审查；真实构建由 CI `images` job 完成。
- GHCR 推送、OIDC keyless 签名、按 digest 的 cosign 验证与 `verify-blob` 原生包验签**全链路**：需要仓库 push tag 后在 GitHub 上实际运行；首个 release 时验证，验证失败工作流会中止发布。当前**尚无任何公开 release 产物**，签名下载路线（第 4、5 节）在首个 `v*` 发布前不可用。
- 原生 systemd 安装器与正式 unit 的**完整实际安装矩阵**（安装/升级边界、重启持久性等，含 CI 上以真实 unit 的端到端验收）：尚未运行；已配置 Ubuntu 22.04/24.04 的 amd64/arm64 正式单元 CI 验收，配置不代表已通过。
- 千台规模压测、长期稳定性与正式安全评估。

## 8. 常见问题

| 现象 | 原因与处理 |
| --- | --- |
| Scout 容器反复退出重启 | 未登记：全新安装必须提供 `--enroll-token-file`；查看 `docker logs sentinel-scout` |
| Scout systemd 服务启动失败 | 看 `journalctl -u sentinel-scout -e`：常见为 `ExecStartPre` 的 doctor 自检未通过（检测为容器/unknown），按 5.3 节核实后用 `--runtime-mode native` 显式声明或改用容器路线 |
| hub 启动报凭证读取失败 | 非特权用户读不到 0600 secret：容器 `user:` 与文件属主 UID/GID 对齐；systemd 路线由安装器创建 `sentinel-hub` 用户并设置属主 |
| `hub migrate` 报 `... and ..._FILE are mutually exclusive` | `SENTINEL_DATABASE_URL` 与 `SENTINEL_DATABASE_URL_FILE` 同时设置；二者只留其一（env 文件里只写 `_FILE` 形式） |
| 安装脚本报"凭证文件权限" | 要求 0600（`chmod 600`），拒绝组/其他可读 |
| 安装脚本报"状态目录非空" | 疑似已有安装：原生路线仅支持全新安装，保留身份和队列排查；当前没有自动升级/续装，不能通过删除身份绕过保护 |
| `docker ps` 正常但脚本报"无法访问 Docker 守护进程" | 当前用户无 Docker socket 权限：请用 sudo 或将用户加入 docker 组（脚本不代改宿主配置） |
| systemd 安装器报"容器环境" | `systemd-detect-virt` 判定在容器内：请改用第 4 节 Docker 安装路线 |
| 14222/5440 等端口冲突 | compose 默认端口可经 `deploy/compose/.env` 覆盖；原生 Hub 监听地址用 `--bind` 调整 |
