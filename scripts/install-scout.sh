#!/usr/bin/env bash
#
# Sentinel Scout 发布镜像安装脚本
#
# 设计边界（详见 docs/deployment.md）：
# - 下载/验证/运行分离：--plan（离线预览）、--dry-run（只读验证+预览，不改状态）、
#   --verify-only（完整验证后退出）、--fetch-only（验证+拉取，不运行）、默认（完整安装）。
# - 签名验证采用精确 digest + 精确 certificate-identity（本仓库 release.yml + tag ref）
#   + 精确 issuer，不使用任意正则、不关闭 tlog 校验；验证失败立即退出，
#   绝不拉取或运行特权 Scout 容器。
# - 凭证只通过 0600 文件挂载注入（*_FILE），不出现在 argv 与日志中。
# - 拒绝覆盖已存在容器与非空状态目录；--resume 仅跳过 init（enroll 幂等可重试）。
# - 本脚本不提供自动升级（升级由 Scout 后续功能承担），不安装 Docker，不修改宿主配置。
#
# 依赖：docker（含 buildx 插件）、cosign、python3。目标系统：Ubuntu 22.04/24.04。

set -euo pipefail

readonly DEFAULT_IMAGE="ghcr.io/j1a-wei/sentinel-scout"
readonly CERT_IDENTITY_PREFIX="https://github.com/J1a-wei/Sentinel/.github/workflows/release.yml"
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly DEFAULT_STATE_DIR="/var/lib/sentinel"
readonly DEFAULT_CONFIG_DIR="/etc/sentinel"
readonly DEFAULT_CONTAINER="sentinel-scout"

VERSION=""
IMAGE="$DEFAULT_IMAGE"
HUB_URL=""
NATS_URL=""
NATS_TOKEN_FILE=""
ENROLL_TOKEN_FILE=""
STATE_DIR="$DEFAULT_STATE_DIR"
CONFIG_DIR="$DEFAULT_CONFIG_DIR"
CONTAINER_NAME="$DEFAULT_CONTAINER"
ASSET_NAME=""
GROUP_ID=""
INTERVAL=""
MODE="install"
RESUME="false"

DIGEST=""
IMAGE_REF=""
NATS_MOUNT=()

die() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

info() {
    printf '%s\n' "$*"
}

usage() {
    cat <<'EOF'
用法：install-scout.sh --version vX.Y.Z [选项]

必选：
  --version vX.Y.Z        要安装的发布版本（对应 git tag，如 v0.1.0）
  --hub-url URL           Hub 地址（登记用，如 https://sentinel-hub.example.com）
  --nats-url URL          NATS 地址（如 nats://sentinel-nats.example.com:4222）

连接凭证（可选，均为 0600 文件路径，内容不会进入 argv 或日志）：
  --nats-token-file F     NATS token 文件（复制到 /etc/sentinel/nats-token，0600）
  --enroll-token-file F   管理员登记令牌文件（仅 enroll 一次性挂载，用后删除副本）

安装位置（可选）：
  --state-dir DIR         Scout 持久状态目录（默认 /var/lib/sentinel，需 root）
  --config-dir DIR        配置目录（默认 /etc/sentinel，需 root）
  --container-name NAME   容器名（默认 sentinel-scout）
  --image REPO            镜像仓库（默认 ghcr.io/j1a-wei/sentinel-scout，主要供测试）

登记信息（可选）：
  --asset-name NAME       资产显示名（默认安装 ID；限 [A-Za-z0-9._-]，最长 64）
  --group-id ID           管理分组 ID
  --interval SECONDS      采集上报间隔（5..3600，默认 30）

模式（可选，默认完整安装）：
  --plan                  离线预览：不联网、不检查 docker/cosign，只打印安装计划
  --dry-run               只读演练：解析 digest 并完成签名验证，打印计划，不写任何状态
  --verify-only           完整验证（digest + 平台 + 签名）后退出，不拉取不运行
  --fetch-only            验证并拉取镜像，不运行容器（下载/运行分离供审查）
  --resume                续装：状态目录非空但容器不存在时，跳过 init 直接启动
                          （enroll 若提供令牌仍会执行，服务端幂等）

安全行为：
  - 验证失败（digest 解析、平台缺失、cosign 任何失败）立即退出，不运行 Docker 容器。
  - 全新安装必须提供 --enroll-token-file：未登记的 Scout 启动后会立即退出，不会假报成功；
    已登记主机重建容器用 --resume（可省略令牌）。
  - 启动后验证容器仍在运行；已退出则报错并指向 docker logs。
  - 已存在同名容器或非空状态目录时拒绝安装（本脚本不覆盖、不升级）。
  - 升级由 Scout 内置功能（后续版本）承担，本脚本不假装提供安全自动升级。
EOF
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --version)
                [ $# -ge 2 ] || die "--version 需要参数"
                VERSION=$2
                shift 2
                ;;
            --hub-url)
                [ $# -ge 2 ] || die "--hub-url 需要参数"
                HUB_URL=$2
                shift 2
                ;;
            --nats-url)
                [ $# -ge 2 ] || die "--nats-url 需要参数"
                NATS_URL=$2
                shift 2
                ;;
            --nats-token-file)
                [ $# -ge 2 ] || die "--nats-token-file 需要参数"
                NATS_TOKEN_FILE=$2
                shift 2
                ;;
            --enroll-token-file)
                [ $# -ge 2 ] || die "--enroll-token-file 需要参数"
                ENROLL_TOKEN_FILE=$2
                shift 2
                ;;
            --state-dir)
                [ $# -ge 2 ] || die "--state-dir 需要参数"
                STATE_DIR=$2
                shift 2
                ;;
            --config-dir)
                [ $# -ge 2 ] || die "--config-dir 需要参数"
                CONFIG_DIR=$2
                shift 2
                ;;
            --container-name)
                [ $# -ge 2 ] || die "--container-name 需要参数"
                CONTAINER_NAME=$2
                shift 2
                ;;
            --image)
                [ $# -ge 2 ] || die "--image 需要参数"
                IMAGE=$2
                shift 2
                ;;
            --asset-name)
                [ $# -ge 2 ] || die "--asset-name 需要参数"
                ASSET_NAME=$2
                shift 2
                ;;
            --group-id)
                [ $# -ge 2 ] || die "--group-id 需要参数"
                GROUP_ID=$2
                shift 2
                ;;
            --interval)
                [ $# -ge 2 ] || die "--interval 需要参数"
                INTERVAL=$2
                shift 2
                ;;
            --plan)
                MODE="plan"
                shift
                ;;
            --dry-run)
                MODE="dry-run"
                shift
                ;;
            --verify-only)
                MODE="verify-only"
                shift
                ;;
            --fetch-only)
                MODE="fetch-only"
                shift
                ;;
            --resume)
                RESUME="true"
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "未知参数：$1（使用 --help 查看用法）"
                ;;
        esac
    done
}

validate_inputs() {
    [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$ ]] \
        || die "--version 格式应为 vX.Y.Z（如 v0.1.0）"
    [[ "$IMAGE" =~ ^[a-z0-9./_-]+$ ]] || die "--image 含非法字符"
    check_url_safe() {
        case "$1" in
            *@*) return 1 ;;
            *[[:space:]]*) return 1 ;;
            *"'"*) return 1 ;;
            *'"'*) return 1 ;;
        esac
        return 0
    }
    if [ -n "$HUB_URL" ]; then
        case "$HUB_URL" in
            http://*|https://*) ;;
            *) die "--hub-url 应以 http:// 或 https:// 开头" ;;
        esac
        check_url_safe "$HUB_URL" || die "--hub-url 不应包含 userinfo（user:pass@host）、空格或引号：凭证不得进入 argv/env 文件/日志，请在受控边界内使用 *_FILE 注入"
    fi
    if [ -n "$NATS_URL" ]; then
        case "$NATS_URL" in
            nats://*|tls://*) ;;
            *) die "--nats-url 应以 nats:// 或 tls:// 开头" ;;
        esac
        check_url_safe "$NATS_URL" || die "--nats-url 不应包含 userinfo、空格或引号：token 请用 --nats-token-file 注入"
    fi
    if [ -n "$ASSET_NAME" ]; then
        [[ "$ASSET_NAME" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die "--asset-name 仅允许 [A-Za-z0-9._-]，最长 64"
    fi
    if [ -n "$GROUP_ID" ]; then
        [[ "$GROUP_ID" =~ ^[A-Za-z0-9-]{1,64}$ ]] || die "--group-id 仅允许 [A-Za-z0-9-]，最长 64"
    fi
    if [ -n "$INTERVAL" ]; then
        [[ "$INTERVAL" =~ ^[0-9]+$ ]] || die "--interval 应为整数秒"
        if ! { [ "$INTERVAL" -ge 5 ] && [ "$INTERVAL" -le 3600 ]; }; then
            die "--interval 范围 5..3600"
        fi
    fi
    if [ "$MODE" != "plan" ] && [ "$MODE" != "verify-only" ]; then
        [ -n "$HUB_URL" ] || die "缺少 --hub-url（--plan / --verify-only 模式可省略）"
        [ -n "$NATS_URL" ] || die "缺少 --nats-url（--plan / --verify-only 模式可省略）"
    fi
}

detect_arch() {
    case "$(uname -m)" in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *)
            die "不支持的架构 $(uname -m)：当前发布镜像仅提供 linux/amd64 与 linux/arm64"
            ;;
    esac
}

require_docker() {
    command -v docker >/dev/null 2>&1 \
        || die "未找到 docker。请先安装受支持的 Docker Engine（本脚本不会自动安装或修改宿主配置）"
    docker info >/dev/null 2>&1 \
        || die "无法访问 Docker 守护进程（docker info 失败）。请确认 Docker 已运行且当前用户有权限；脚本不修改宿主权限"
    docker buildx version >/dev/null 2>&1 \
        || die "docker 缺少 buildx 插件（解析镜像 digest 需要 docker buildx imagetools）"
}

require_cosign() {
    command -v cosign >/dev/null 2>&1 \
        || die "未找到 cosign（https://docs.sigstore.dev/cosign/system_config/installation/）。验证签名是安装前置条件"
    cosign version >/dev/null 2>&1 || die "cosign 无法执行（cosign version 失败）"
}

require_python() {
    command -v python3 >/dev/null 2>&1 || die "未找到 python3（manifest 平台解析需要）"
}

resolve_digest() {
    local ref digest
    ref="${IMAGE}:${VERSION}"
    if ! digest=$(docker buildx imagetools inspect --format '{{.Manifest.Digest}}' "$ref" 2>/dev/null); then
        die "无法解析镜像 digest：${ref}。请确认该版本已发布且镜像可拉取"
    fi
    [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || die "镜像 digest 格式异常：${digest}"
    DIGEST=$digest
    IMAGE_REF="${IMAGE}@${DIGEST}"
}

check_platform() {
    local manifest ok
    if ! manifest=$(docker buildx imagetools inspect --format '{{json .Manifest}}' "$IMAGE_REF" 2>/dev/null); then
        die "无法读取镜像 manifest：${IMAGE_REF}"
    fi
    if ! ok=$(python3 -c '
import json
import sys

data = json.loads(sys.argv[1])
arch = sys.argv[2]
found = any(
    (entry.get("platform") or {}).get("os") == "linux"
    and (entry.get("platform") or {}).get("architecture") == arch
    for entry in data.get("manifests", [])
)
print("ok" if found else "missing")
' "$manifest" "$ARCH"); then
        die "镜像 manifest 解析失败（python3）"
    fi
    [ "$ok" = "ok" ] || die "镜像 ${IMAGE_REF} 不包含 linux/${ARCH}（当前主机架构）。请确认该版本提供了本架构镜像"
}

verify_signature() {
    local identity
    identity="${CERT_IDENTITY_PREFIX}@refs/tags/${VERSION}"
    info "验证镜像签名：${IMAGE_REF}"
    info "  certificate-identity: ${identity}"
    info "  certificate-oidc-issuer: ${OIDC_ISSUER}"
    if ! cosign verify \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "$OIDC_ISSUER" \
        "$IMAGE_REF" >/dev/null; then
        die "签名验证失败：${IMAGE_REF}。已中止，未拉取/未运行任何镜像。请勿绕过验证使用未签名镜像"
    fi
    info "签名验证通过"
}

container_exists() {
    docker ps -a --format '{{.Names}}' | grep -Fxq "$CONTAINER_NAME"
}

state_dir_populated() {
    [ -d "$STATE_DIR" ] && [ -n "$(ls -A "$STATE_DIR")" ]
}

check_install_boundaries() {
    if [ -z "$ENROLL_TOKEN_FILE" ]; then
        if [ "$RESUME" = "true" ]; then
            info "--resume 未提供登记令牌：跳过 enroll（假定该主机已在 Hub 登记过）"
        else
            die "全新安装需要 --enroll-token-file 提供管理员登记令牌：未登记的 Scout 启动后会立即退出。已登记主机重建容器请用 --resume"
        fi
    fi
    if container_exists; then
        die "容器 ${CONTAINER_NAME} 已存在。本脚本不覆盖已有安装，也不提供升级（升级由 Scout 后续功能承担）；如确需重装请先人工确认并 docker rm"
    fi
    if [ "$RESUME" = "true" ]; then
        state_dir_populated || die "--resume 需要已存在的非空状态目录（当前 ${STATE_DIR} 为空或不存在）"
    else
        if state_dir_populated; then
            die "状态目录 ${STATE_DIR} 非空，疑似已有安装。核对后可用 --resume 续装（跳过 init），或人工确认清理后重装；本脚本不覆盖已有数据"
        fi
    fi
    local path
    for path in /proc /sys /etc /usr/lib/os-release /var/lib/dpkg; do
        [ -e "$path" ] || die "宿主机缺少 ${path}；当前安装假设 Ubuntu/Debian 系主机（只读挂载宿主数据）"
    done
}

ensure_dirs() {
    if ! mkdir -p "$STATE_DIR" "$CONFIG_DIR"; then
        die "无法创建 ${STATE_DIR} 或 ${CONFIG_DIR}。默认路径需要 root（sudo）；或用 --state-dir/--config-dir 指定可写目录"
    fi
    chmod 700 "$STATE_DIR" "$CONFIG_DIR"
}

install_token_file() {
    local src=$1 dst=$2 perms
    [ -f "$src" ] || die "凭证文件不存在：$src"
    perms=$(stat -c '%a' "$src")
    [ "$perms" = "600" ] || [ "$perms" = "400" ] \
        || die "凭证文件 ${src} 权限为 ${perms}，要求 0600（请 chmod 600）。拒绝使用组/其他可读的凭证"
    install -m 600 "$src" "$dst"
}

write_env_file() {
    local path="${CONFIG_DIR}/scout.env"
    {
        printf 'SENTINEL_HOST_ROOT=/host\n'
        printf 'SENTINEL_STATE_DIR=/var/lib/sentinel\n'
        printf 'SENTINEL_HUB_URL=%s\n' "$HUB_URL"
        printf 'SENTINEL_NATS_URL=%s\n' "$NATS_URL"
        [ -n "$INTERVAL" ] && printf 'SENTINEL_INTERVAL_SECONDS=%s\n' "$INTERVAL"
        [ -n "$NATS_TOKEN_FILE" ] && printf 'SENTINEL_NATS_TOKEN_FILE=/run/secrets/nats-token\n'
        [ -n "$ASSET_NAME" ] && printf 'SENTINEL_ASSET_NAME=%s\n' "$ASSET_NAME"
        [ -n "$GROUP_ID" ] && printf 'SENTINEL_GROUP_ID=%s\n' "$GROUP_ID"
    } >"$path"
    chmod 600 "$path"
    # 可选行为空时 [ -n ... ] 返回非零，不能作为函数退出码
    return 0
}

init_identity() {
    info "初始化 Scout 身份（生成持久 Ed25519 身份，写入 ${STATE_DIR}）"
    docker run --rm \
        -v "${STATE_DIR}:/var/lib/sentinel" \
        --env-file "${CONFIG_DIR}/scout.env" \
        "$IMAGE_REF" init
}

enroll_installation() {
    local rc=0
    info "登记安装身份（管理员令牌仅本次一次性挂载，副本用后删除）"
    # --network host：登记容器需与常驻 Scout 一致地看到宿主网络（Hub 常为宿主侧地址）
    docker run --rm \
        --network host \
        -v "${STATE_DIR}:/var/lib/sentinel" \
        -v "${CONFIG_DIR}/enroll-token:/run/secrets/enroll-token:ro" \
        -e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/enroll-token \
        --env-file "${CONFIG_DIR}/scout.env" \
        "$IMAGE_REF" enroll || rc=$?
    rm -f "${CONFIG_DIR}/enroll-token"
    [ "$rc" -eq 0 ] || die "enroll 失败（退出码 ${rc}）。登记在服务端幂等：修正问题后重新运行并加 --resume"
}

start_scout() {
    info "启动特权 Scout 容器（host network/PID 视图，宿主数据只读挂载到 /host）"
    docker run -d \
        --name "$CONTAINER_NAME" \
        --restart unless-stopped \
        --privileged \
        --network host \
        --pid host \
        -v /proc:/host/proc:ro \
        -v /sys:/host/sys:ro \
        -v /etc:/host/etc:ro \
        -v /usr/lib/os-release:/host/usr/lib/os-release:ro \
        -v /var/lib/dpkg:/host/var/lib/dpkg:ro \
        -v "${STATE_DIR}:/var/lib/sentinel" \
        ${NATS_MOUNT[@]+"${NATS_MOUNT[@]}"} \
        --env-file "${CONFIG_DIR}/scout.env" \
        "$IMAGE_REF" >/dev/null || die "容器启动失败。可用 --resume 重新运行（跳过 init）"
    # 验证容器仍在运行：未登记/配置错误的 Scout 会立即退出，不能默认报告成功
    sleep 3
    if [ -z "$(docker ps --filter "name=^/${CONTAINER_NAME}$" --filter "status=running" --format '{{.Names}}')" ]; then
        die "容器 ${CONTAINER_NAME} 启动后已退出（未运行）。排查：docker logs ${CONTAINER_NAME}"
    fi
}

print_run_summary() {
    if [ -n "$ENROLL_TOKEN_FILE" ]; then
        info "安装完成：容器 ${CONTAINER_NAME} 运行中（镜像 ${IMAGE_REF}，已验证签名；登记命令退出码 0）。"
    else
        info "安装完成：容器 ${CONTAINER_NAME} 运行中（镜像 ${IMAGE_REF}，已验证签名）。--resume 未重新执行登记，请通过日志或 Hub 侧确认登记状态。"
    fi
    info "  状态查询（只读，常驻运行时可用）：docker exec ${CONTAINER_NAME} scout status"
    info "  日志（含登记/上报情况）：docker logs -f ${CONTAINER_NAME}"
    info "  停止：docker stop ${CONTAINER_NAME}"
    info "注意：本脚本不验证 Hub 侧数据入库（仅确认本地容器运行中）；也不提供升级，Scout 内置升级功能交付后由其接管。"
}

print_plan() {
    local offline=$1
    local ref identity
    if [ "$offline" = "true" ]; then
        ref="${IMAGE}:${VERSION}（安装时解析为 digest 并验证）"
        identity="${CERT_IDENTITY_PREFIX}@refs/tags/${VERSION}"
    else
        ref="$IMAGE_REF"
        identity="${CERT_IDENTITY_PREFIX}@refs/tags/${VERSION}"
    fi
    info "================ 安装计划 ================"
    info "版本：${VERSION}"
    info "镜像：${ref}"
    info "验证：cosign verify --certificate-identity '${identity}' --certificate-oidc-issuer '${OIDC_ISSUER}' <镜像@digest>"
    info "主机架构：$(uname -m)（要求镜像包含 linux/${ARCH}）"
    info "容器名：${CONTAINER_NAME}"
    info "状态目录：${STATE_DIR}（0700，已存在且非空则拒绝，除非 --resume）"
    info "配置目录：${CONFIG_DIR}（scout.env 0600${NATS_TOKEN_FILE:+，nats-token 0600}）"
    info "宿主只读挂载：/proc /sys /etc /usr/lib/os-release /var/lib/dpkg -> /host"
    info "运行视图：--privileged --network host --pid host（本批需要宿主网络/PID 视图做端口与进程采集）"
    info "步骤：验证签名 -> docker pull <镜像@digest> -> init（--resume 跳过） -> enroll（全新安装必须提供令牌） -> docker run -d -> 确认容器运行"
    info "==========================================="
}

run_install() {
    check_install_boundaries
    ensure_dirs
    if [ -n "$NATS_TOKEN_FILE" ]; then
        install_token_file "$NATS_TOKEN_FILE" "${CONFIG_DIR}/nats-token"
        NATS_MOUNT=(-v "${CONFIG_DIR}/nats-token:/run/secrets/nats-token:ro")
    fi
    write_env_file
    info "拉取已验证镜像：${IMAGE_REF}"
    docker pull "$IMAGE_REF" || die "镜像拉取失败：${IMAGE_REF}"
    if [ "$RESUME" != "true" ]; then
        init_identity || die "scout init 失败。状态目录已保留：修正后重新运行并加 --resume"
    fi
    if [ -n "$ENROLL_TOKEN_FILE" ]; then
        install_token_file "$ENROLL_TOKEN_FILE" "${CONFIG_DIR}/enroll-token"
        enroll_installation
    fi
    start_scout || die "容器启动失败。可用 --resume 重新运行（跳过 init）"
    print_run_summary
}

main() {
    parse_args "$@"
    validate_inputs
    detect_arch

    if [ "$MODE" = "plan" ]; then
        print_plan "true"
        exit 0
    fi

    require_docker
    require_cosign
    require_python

    resolve_digest
    info "已解析 digest：${IMAGE}:${VERSION} -> ${IMAGE_REF}"
    check_platform
    verify_signature

    case "$MODE" in
        verify-only)
            info "验证完成（--verify-only）：未拉取、未运行任何容器"
            exit 0
            ;;
        dry-run)
            print_plan "false"
            info "--dry-run：未拉取、未运行容器、未写入任何状态"
            exit 0
            ;;
        fetch-only)
            info "拉取已验证镜像（--fetch-only，不运行容器）：${IMAGE_REF}"
            docker pull "$IMAGE_REF" || die "镜像拉取失败：${IMAGE_REF}"
            info "拉取完成。审查后可去掉 --fetch-only 执行完整安装"
            exit 0
            ;;
        install)
            run_install
            ;;
        *)
            die "内部错误：未知模式 ${MODE}"
            ;;
    esac
}

main "$@"
