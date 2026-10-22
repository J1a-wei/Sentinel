#!/usr/bin/env bash
#
# install-scout.sh 的 mock 测试：用假的 docker/cosign 命令验证安装脚本的行为契约：
# - 签名/平台/digest 验证失败时绝不调用 docker pull / docker run；
# - --dry-run 不写入任何状态（目录、env、凭证副本）；
# - cosign 调用参数精确（identity/issuer），不含 regexp、不关 tlog；
# - 凭证不进入 argv/日志；已存在容器/非空状态目录时拒绝；
# - --resume 边界正确；token 文件权限强制 0600。
#
# 依赖：bash、python3、coreutils。不需要真实 Docker/cosign。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
INSTALLER="${ROOT}/scripts/install-scout.sh"

PASS=0
FAIL=0

ok() {
    PASS=$((PASS + 1))
    printf 'ok   %s\n' "$1"
}

fail() {
    FAIL=$((FAIL + 1))
    printf 'FAIL %s: %s\n' "$1" "$2"
}

expect_nonzero() {
    local name=$1 rc=$2
    if [ "$rc" -ne 0 ]; then
        ok "$name"
    else
        fail "$name" "期望非零退出码，实际 0"
    fi
}

assert_equals() {
    local name=$1 want=$2 got=$3
    if [ "$want" = "$got" ]; then
        ok "$name"
    else
        fail "$name" "期望 [$want] 实际 [$got]"
    fi
}

assert_exit() {
    local name=$1 want=$2 got=$3
    if [ "$want" -eq "$got" ]; then
        ok "$name"
    else
        fail "$name" "期望退出码 $want，实际 $got"
    fi
}

assert_contains() {
    local name=$1 file=$2 needle=$3
    if grep -Fq -- "$needle" "$file"; then
        ok "$name"
    else
        fail "$name" "未在 $(basename "$file") 中找到：$needle"
    fi
}

assert_not_contains() {
    local name=$1 file=$2 needle=$3
    if grep -Fq -- "$needle" "$file"; then
        fail "$name" "不应在 $(basename "$file") 中出现：$needle"
    else
        ok "$name"
    fi
}

assert_mode() {
    local name=$1 path=$2 want=$3
    local got
    got=$(stat -c '%a' "$path" 2>/dev/null || echo missing)
    if [ "$got" = "$want" ] || { [ "$got" = "missing" ] && [ "$want" = "missing" ]; }; then
        ok "$name"
    else
        fail "$name" "期望权限 $want，实际 $got（$path）"
    fi
}

# ---------------------------------------------------------------------------
# mock 工具
# ---------------------------------------------------------------------------

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MOCKBIN="${WORK}/bin"
BASICBIN="${WORK}/basic"
MOCK_STATE="${WORK}/mockstate"
export MOCK_LOG="${WORK}/docker.log"
export COSIGN_LOG="${WORK}/cosign.log"
export MOCK_STATE
export MOCK_LOG
export COSIGN_LOG
mkdir -p "$MOCKBIN" "$MOCK_STATE" "${WORK}/bin-cosign" "${WORK}/bin-docker" "${BASICBIN}"
: >"$MOCK_LOG"
: >"$COSIGN_LOG"

# mock docker：记录调用，按 flag 文件控制失败，模拟 buildx inspect 输出
cat >"${MOCKBIN}/docker" <<'MOCK'
#!/usr/bin/env bash
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
case "$1" in
    info)
        [ -e "$MOCK_STATE/docker-info-fail" ] && exit 1
        exit 0
        ;;
    buildx)
        if [ "$2" = "version" ]; then
            exit 0
        fi
        if [ "$2" = "imagetools" ] && [ "$3" = "inspect" ]; then
            [ -e "$MOCK_STATE/inspect-fail" ] && exit 1
            shift 3
            fmt=""
            ref=""
            while [ $# -gt 0 ]; do
                if [ "$1" = "--format" ]; then
                    fmt=$2
                    shift 2
                else
                    ref=$1
                    shift
                fi
            done
            if [ "$fmt" = "{{.Manifest.Digest}}" ]; then
                echo "${MOCK_DIGEST:-sha256:1111111111111111111111111111111111111111111111111111111111111111}"
            elif [ "$fmt" = "{{json .Manifest}}" ]; then
                python3 - "${MOCK_PLATFORMS:-linux/amd64,linux/arm64}" <<'PY'
import json
import sys

digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
manifests = []
for plat in sys.argv[1].split(","):
    parts = plat.split("/")
    manifests.append({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": digest,
        "size": 1234,
        "platform": {"architecture": parts[1], "os": parts[0]},
    })
print(json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.oci.image.index.v1+json",
    "digest": digest,
    "size": 4096,
    "manifests": manifests,
}, indent=2))
PY
            else
                echo "mock: unsupported format $fmt" >&2
                exit 1
            fi
            exit 0
        fi
        exit 0
        ;;
    ps)
        # 两种调用：存在性检查（ps -a --format）与运行检查（ps --filter status=running）
        running_filter=false
        for a in "$@"; do
            [ "$a" = "status=running" ] && running_filter=true
        done
        if $running_filter; then
            [ -e "$MOCK_STATE/container-exited" ] || echo "test-scout"
            exit 0
        fi
        if [ -e "$MOCK_STATE/existing-container" ]; then
            echo "test-scout"
        fi
        exit 0
        ;;
    pull)
        [ -e "$MOCK_STATE/pull-fail" ] && exit 1
        exit 0
        ;;
    run)
        [ -e "$MOCK_STATE/run-fail" ] && exit 1
        exit 0
        ;;
    *)
        exit 0
        ;;
esac
MOCK
chmod +x "${MOCKBIN}/docker"

# mock cosign：记录参数，按 flag 文件控制失败
cat >"${WORK}/bin-cosign/cosign" <<'MOCK'
#!/usr/bin/env bash
printf 'cosign %s\n' "$*" >> "$COSIGN_LOG"
if [ "$1" = "version" ]; then
    exit 0
fi
[ -e "$MOCK_STATE/cosign-fail" ] && exit 1
exit 0
MOCK
chmod +x "${WORK}/bin-cosign/cosign"
cp "${MOCKBIN}/docker" "${WORK}/bin-docker/docker"

# 基础命令目录（无 docker/cosign），用于模拟工具缺失
for c in bash sleep uname stat install mkdir chmod ls rm cat python3 grep; do
    ln -s "$(command -v "$c")" "${BASICBIN}/$c"
done

# 运行被测脚本：MODE 选择 PATH 组合
#   full     = mock docker + mock cosign
#   nodocker = 只有 mock cosign（模拟 docker 缺失）
#   nocosign = 只有 mock docker（模拟 cosign 缺失）
#   offline  = 只有基础命令（模拟两者都缺失，用于 --plan）
run_installer() {
    local pathmode=$1
    shift
    local path
    case "$pathmode" in
        full) path="${MOCKBIN}:${WORK}/bin-cosign:${BASICBIN}" ;;
        nodocker) path="${WORK}/bin-cosign:${BASICBIN}" ;;
        nocosign) path="${MOCKBIN}:${BASICBIN}" ;;
        offline) path="${BASICBIN}" ;;
        *) fail "run_installer" "未知 PATH 模式 $pathmode"; return 1 ;;
    esac
    env MOCK_LOG="$MOCK_LOG" COSIGN_LOG="$COSIGN_LOG" MOCK_STATE="$MOCK_STATE" \
        PATH="$path" bash "$INSTALLER" "$@" \
        >"${WORK}/stdout.txt" 2>"${WORK}/stderr.txt"
    echo $?
}

reset_env() {
    rm -f "$MOCK_STATE"/*
    : >"$MOCK_LOG"
    : >"$COSIGN_LOG"
}

STATE="${WORK}/state"
CONFIG="${WORK}/config"
DEFAULT_ARGS=(
    --version v0.1.0
    --image registry.example/test-scout
    --hub-url http://hub.example:8080
    --nats-url nats://nats.example:4222
    --state-dir "$STATE"
    --config-dir "$CONFIG"
    --container-name test-scout
)

NATS_TOKEN_SECRET="fake-nats-secret-DO-NOT-PRINT"
ENROLL_TOKEN_SECRET="fake-enroll-secret-DO-NOT-PRINT"
DIGEST="sha256:1111111111111111111111111111111111111111111111111111111111111111"

make_token_files() {
    umask 077
    printf 'fake-nats-secret-DO-NOT-PRINT' >"${WORK}/nats.token"
    printf 'fake-enroll-secret-DO-NOT-PRINT' >"${WORK}/enroll.token"
}

# ---------------------------------------------------------------------------
# 1. --plan：离线，无 docker/cosign 也可预览，不写状态
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer offline --plan "${DEFAULT_ARGS[@]}")
assert_exit "plan/退出码0" 0 "$rc"
assert_contains "plan/输出包含计划" "${WORK}/stdout.txt" "安装计划"
assert_mode "plan/未创建状态目录" "$STATE" missing
assert_mode "plan/未创建配置目录" "$CONFIG" missing
assert_equals "plan/未调用docker" "" "$(cat "$MOCK_LOG")"
assert_equals "plan/未调用cosign" "" "$(cat "$COSIGN_LOG")"

# ---------------------------------------------------------------------------
# 2. --dry-run：真实走 digest/平台/签名验证（只读），但不 pull/run/写状态
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer full --dry-run "${DEFAULT_ARGS[@]}")
assert_exit "dry-run/退出码0" 0 "$rc"
assert_contains "dry-run/解析了digest" "${WORK}/stdout.txt" "已解析 digest"
assert_contains "dry-run/打印了计划" "${WORK}/stdout.txt" "安装计划"
assert_not_contains "dry-run/未docker-pull" "$MOCK_LOG" "docker pull"
assert_not_contains "dry-run/未docker-run" "$MOCK_LOG" "docker run"
assert_mode "dry-run/未创建状态目录" "$STATE" missing
assert_mode "dry-run/未创建配置目录" "$CONFIG" missing

# ---------------------------------------------------------------------------
# 3. cosign 验证失败：立即退出，绝不 pull / run
# ---------------------------------------------------------------------------
reset_env
touch "$MOCK_STATE/cosign-fail"
rc=$(run_installer full --dry-run "${DEFAULT_ARGS[@]}")
expect_nonzero "cosign失败/非零退出" "$rc"
assert_contains "cosign失败/报验证失败" "${WORK}/stderr.txt" "签名验证失败"
assert_not_contains "cosign失败/未docker-pull" "$MOCK_LOG" "docker pull"
assert_not_contains "cosign失败/未docker-run" "$MOCK_LOG" "docker run"
assert_mode "cosign失败/未创建状态目录" "$STATE" missing

# ---------------------------------------------------------------------------
# 4. digest 解析失败：退出，不验证不拉取
# ---------------------------------------------------------------------------
reset_env
touch "$MOCK_STATE/inspect-fail"
rc=$(run_installer full --verify-only "${DEFAULT_ARGS[@]}")
expect_nonzero "digest失败/非零退出" "$rc"
assert_contains "digest失败/报digest错误" "${WORK}/stderr.txt" "无法解析镜像 digest"
assert_not_contains "digest失败/未cosign-verify" "$COSIGN_LOG" "verify"
assert_not_contains "digest失败/未docker-pull" "$MOCK_LOG" "docker pull"

# ---------------------------------------------------------------------------
# 5. docker 缺失
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer nodocker --dry-run "${DEFAULT_ARGS[@]}")
expect_nonzero "无docker/非零退出" "$rc"
assert_contains "无docker/明确提示" "${WORK}/stderr.txt" "未找到 docker"

# ---------------------------------------------------------------------------
# 6. cosign 缺失
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer nocosign --dry-run "${DEFAULT_ARGS[@]}")
expect_nonzero "无cosign/非零退出" "$rc"
assert_contains "无cosign/明确提示" "${WORK}/stderr.txt" "未找到 cosign"

# ---------------------------------------------------------------------------
# 7. Docker 守护进程不可达
# ---------------------------------------------------------------------------
reset_env
touch "$MOCK_STATE/docker-info-fail"
rc=$(run_installer full --dry-run "${DEFAULT_ARGS[@]}")
expect_nonzero "daemon不可达/非零退出" "$rc"
assert_contains "daemon不可达/明确提示" "${WORK}/stderr.txt" "无法访问 Docker 守护进程"
assert_not_contains "daemon不可达/未docker-run" "$MOCK_LOG" "docker run"

# ---------------------------------------------------------------------------
# 8. 架构不匹配（mock 平台列表不含当前架构）
# ---------------------------------------------------------------------------
reset_env
case "$(uname -m)" in
    x86_64) OTHER=arm64 ;;
    aarch64) OTHER=amd64 ;;
    *) OTHER=amd64 ;;
esac
export MOCK_PLATFORMS="linux/${OTHER}"
rc=$(run_installer full --dry-run "${DEFAULT_ARGS[@]}")
unset MOCK_PLATFORMS
expect_nonzero "架构不匹配/非零退出" "$rc"
assert_contains "架构不匹配/明确提示" "${WORK}/stderr.txt" "不包含 linux/"
assert_not_contains "架构不匹配/未docker-pull" "$MOCK_LOG" "docker pull"

# ---------------------------------------------------------------------------
# 9. 完整安装（happy path）：init -> enroll -> start 顺序、参数、权限、无泄漏
# ---------------------------------------------------------------------------
reset_env
make_token_files
rc=$(run_installer full "${DEFAULT_ARGS[@]}" \
    --nats-token-file "${WORK}/nats.token" \
    --enroll-token-file "${WORK}/enroll.token" \
    --asset-name test-host-1 --interval 15)
assert_exit "安装/退出码0" 0 "$rc"
# 顺序：ps 边界检查 -> pull -> init -> enroll -> run -d
assert_contains "安装/执行了pull" "$MOCK_LOG" "docker pull registry.example/test-scout@${DIGEST}"
assert_contains "安装/init一次性运行" "$MOCK_LOG" " init"
assert_contains "安装/enroll挂载令牌" "$MOCK_LOG" "-v ${CONFIG}/enroll-token:/run/secrets/enroll-token:ro"
assert_contains "安装/enroll使用宿主网络" "$MOCK_LOG" "docker run --rm --network host"
assert_contains "安装/enroll经_FILE注入" "$MOCK_LOG" "-e SENTINEL_ADMIN_TOKEN_FILE=/run/secrets/enroll-token"
assert_contains "安装/最终启动" "$MOCK_LOG" "docker run -d"
assert_contains "安装/启动后验证运行状态" "$MOCK_LOG" "status=running"
# 启动参数：特权、宿主视图、只读挂载、digest 引用、env 文件、NATS token 挂载
assert_contains "安装/按digest运行" "$MOCK_LOG" "registry.example/test-scout@${DIGEST}"
assert_contains "安装/特权容器" "$MOCK_LOG" "--privileged"
assert_contains "安装/宿主网络视图" "$MOCK_LOG" "--network host"
assert_contains "安装/宿主PID视图" "$MOCK_LOG" "--pid host"
assert_contains "安装/proc只读挂载" "$MOCK_LOG" "-v /proc:/host/proc:ro"
assert_contains "安装/etc只读挂载" "$MOCK_LOG" "-v /etc:/host/etc:ro"
assert_contains "安装/os-release显式挂载" "$MOCK_LOG" "-v /usr/lib/os-release:/host/usr/lib/os-release:ro"
assert_contains "安装/dpkg只读挂载" "$MOCK_LOG" "-v /var/lib/dpkg:/host/var/lib/dpkg:ro"
assert_contains "安装/状态目录挂载" "$MOCK_LOG" "-v ${STATE}:/var/lib/sentinel"
assert_contains "安装/env文件注入" "$MOCK_LOG" "--env-file ${CONFIG}/scout.env"
assert_contains "安装/NATStoken文件挂载" "$MOCK_LOG" "-v ${CONFIG}/nats-token:/run/secrets/nats-token:ro"
# 状态与权限
assert_mode "安装/状态目录0700" "$STATE" 700
assert_mode "安装/配置目录0700" "$CONFIG" 700
assert_mode "安装/env文件0600" "${CONFIG}/scout.env" 600
assert_mode "安装/nats-token副本0600" "${CONFIG}/nats-token" 600
assert_mode "安装/enroll副本用后删除" "${CONFIG}/enroll-token" missing
# cosign 精确参数
assert_contains "安装/cosign精确identity" "$COSIGN_LOG" \
    "--certificate-identity https://github.com/J1a-wei/Sentinel/.github/workflows/release.yml@refs/tags/v0.1.0"
assert_contains "安装/cosign精确issuer" "$COSIGN_LOG" \
    "--certificate-oidc-issuer https://token.actions.githubusercontent.com"
assert_not_contains "安装/cosign无regexp" "$COSIGN_LOG" "regexp"
assert_not_contains "安装/cosign不关tlog" "$COSIGN_LOG" "insecure-ignore-tlog"
# 凭证不泄漏到 argv/日志/env 文件
assert_not_contains "安装/NATS凭证不入日志" "$MOCK_LOG" "$NATS_TOKEN_SECRET"
assert_not_contains "安装/NATS凭证不入cosign日志" "$COSIGN_LOG" "$NATS_TOKEN_SECRET"
assert_not_contains "安装/登记凭证不入日志" "$MOCK_LOG" "$ENROLL_TOKEN_SECRET"
assert_not_contains "安装/凭证不入env文件" "${CONFIG}/scout.env" "$NATS_TOKEN_SECRET"
assert_not_contains "安装/登记凭证不入env文件" "${CONFIG}/scout.env" "$ENROLL_TOKEN_SECRET"
assert_contains "安装/输出安装完成" "${WORK}/stdout.txt" "运行中"

# ---------------------------------------------------------------------------
# 9b. 全新安装未提供登记令牌：拒绝（未登记 Scout 会立即退出），不启动
# ---------------------------------------------------------------------------
reset_env
make_token_files
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --nats-token-file "${WORK}/nats.token")
expect_nonzero "无登记凭证/非零退出" "$rc"
assert_contains "无登记凭证/明确要求" "${WORK}/stderr.txt" "--enroll-token-file"
assert_not_contains "无登记凭证/未启动容器" "$MOCK_LOG" "docker run -d"

# ---------------------------------------------------------------------------
# 9c. 启动后容器退出（未运行）：不声称安装成功
# ---------------------------------------------------------------------------
reset_env
make_token_files
touch "$MOCK_STATE/container-exited"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" \
    --nats-token-file "${WORK}/nats.token" \
    --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "容器退出/非零退出" "$rc"
assert_contains "容器退出/指向日志排查" "${WORK}/stderr.txt" "docker logs"
assert_not_contains "容器退出/不报完成" "${WORK}/stdout.txt" "运行中"

# ---------------------------------------------------------------------------
# 10. 已存在容器：拒绝，不 pull / run
# ---------------------------------------------------------------------------
reset_env
make_token_files
touch "$MOCK_STATE/existing-container"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "已有容器/非零退出" "$rc"
assert_contains "已有容器/明确拒绝" "${WORK}/stderr.txt" "已存在"
assert_not_contains "已有容器/未docker-pull" "$MOCK_LOG" "docker pull"
assert_not_contains "已有容器/未docker-run" "$MOCK_LOG" "docker run"

# ---------------------------------------------------------------------------
# 11. 状态目录非空：拒绝（幂等边界）
# ---------------------------------------------------------------------------
reset_env
make_token_files
mkdir -p "$STATE"
touch "$STATE/identity.json"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "状态非空/非零退出" "$rc"
assert_contains "状态非空/明确拒绝" "${WORK}/stderr.txt" "非空"
assert_not_contains "状态非空/未docker-run" "$MOCK_LOG" "docker run"
rm -rf "$STATE"

# ---------------------------------------------------------------------------
# 12. --resume 且状态为空：明确报错
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer full --resume "${DEFAULT_ARGS[@]}")
expect_nonzero "resume空状态/非零退出" "$rc"
assert_contains "resume空状态/明确提示" "${WORK}/stderr.txt" "--resume 需要已存在的非空状态目录"

# ---------------------------------------------------------------------------
# 13. --resume 且状态非空：跳过 init，直接启动
# ---------------------------------------------------------------------------
reset_env
mkdir -p "$STATE"
touch "$STATE/identity.json"
rc=$(run_installer full --resume "${DEFAULT_ARGS[@]}")
assert_exit "resume/退出码0" 0 "$rc"
assert_not_contains "resume/跳过init" "$MOCK_LOG" " init"
assert_contains "resume/仍然启动" "$MOCK_LOG" "docker run -d"
assert_not_contains "resume/不声称登记成功" "${WORK}/stdout.txt" "登记命令退出码 0"
rm -rf "$STATE"

# ---------------------------------------------------------------------------
# 14. --verify-only：验证后退出，不拉取不运行
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer full --verify-only "${DEFAULT_ARGS[@]}")
assert_exit "verify-only/退出码0" 0 "$rc"
assert_not_contains "verify-only/未docker-pull" "$MOCK_LOG" "docker pull"
assert_not_contains "verify-only/未docker-run" "$MOCK_LOG" "docker run"
assert_mode "verify-only/未创建状态目录" "$STATE" missing

# ---------------------------------------------------------------------------
# 15. --fetch-only：拉取但不运行
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer full --fetch-only "${DEFAULT_ARGS[@]}")
assert_exit "fetch-only/退出码0" 0 "$rc"
assert_contains "fetch-only/执行了pull" "$MOCK_LOG" "docker pull"
assert_not_contains "fetch-only/未docker-run" "$MOCK_LOG" "docker run"

# ---------------------------------------------------------------------------
# 16. NATS token 文件权限过宽（0644）：拒绝，不 pull / run
# ---------------------------------------------------------------------------
reset_env
printf 'fake-nats-secret' >"${WORK}/wide.token"
chmod 644 "${WORK}/wide.token"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --nats-token-file "${WORK}/wide.token" --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "nats权限过宽/非零退出" "$rc"
assert_contains "nats权限过宽/提示0600" "${WORK}/stderr.txt" "0600"
assert_not_contains "nats权限过宽/未docker-pull" "$MOCK_LOG" "docker pull"
assert_not_contains "nats权限过宽/未docker-run" "$MOCK_LOG" "docker run"

# ---------------------------------------------------------------------------
# 17. enroll token 文件权限过宽（0666）：init 后 enroll 前拒绝
# ---------------------------------------------------------------------------
reset_env
printf 'fake-enroll-secret' >"${WORK}/wide2.token"
chmod 666 "${WORK}/wide2.token"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --enroll-token-file "${WORK}/wide2.token")
expect_nonzero "enroll权限过宽/非零退出" "$rc"
assert_contains "enroll权限过宽/提示0600" "${WORK}/stderr.txt" "0600"
assert_not_contains "enroll权限过宽/未启动容器" "$MOCK_LOG" "docker run -d"

# ---------------------------------------------------------------------------
# 18. init 失败（docker run 失败）：中止并提示 --resume
# ---------------------------------------------------------------------------
reset_env
make_token_files
touch "$MOCK_STATE/run-fail"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "init失败/非零退出" "$rc"
assert_contains "init失败/提示resume" "${WORK}/stderr.txt" "--resume"
assert_not_contains "init失败/未启动容器" "$MOCK_LOG" "docker run -d"
rm -f "$MOCK_STATE/run-fail"

# ---------------------------------------------------------------------------
# 19. 拉取失败：中止，不运行
# ---------------------------------------------------------------------------
reset_env
make_token_files
touch "$MOCK_STATE/pull-fail"
rc=$(run_installer full "${DEFAULT_ARGS[@]}" --enroll-token-file "${WORK}/enroll.token")
expect_nonzero "pull失败/非零退出" "$rc"
assert_not_contains "pull失败/未docker-run" "$MOCK_LOG" "docker run"

# ---------------------------------------------------------------------------
# 20. URL 含 userinfo（user:pass@host）：拒绝（凭证不得进 argv/env/日志）
# ---------------------------------------------------------------------------
reset_env
rc=$(run_installer full --version v0.1.0 --image registry.example/test-scout \
    --hub-url "http://user:pass@hub.example:8080" --nats-url nats://n.example:4222 \
    --state-dir "$STATE" --config-dir "$CONFIG" --container-name test-scout)
expect_nonzero "hub-userinfo/非零退出" "$rc"
assert_contains "hub-userinfo/明确拒绝" "${WORK}/stderr.txt" "userinfo"
assert_not_contains "hub-userinfo/未docker-pull" "$MOCK_LOG" "docker pull"

reset_env
rc=$(run_installer full --version v0.1.0 --image registry.example/test-scout \
    --hub-url http://hub.example:8080 --nats-url "nats://user:pass@n.example:4222" \
    --state-dir "$STATE" --config-dir "$CONFIG" --container-name test-scout)
expect_nonzero "nats-userinfo/非零退出" "$rc"
assert_contains "nats-userinfo/明确拒绝" "${WORK}/stderr.txt" "userinfo"

# tls:// NATS 地址可接受（仅校验格式，不验证可达性）
reset_env
rc=$(run_installer full --verify-only --version v0.1.0 --image registry.example/test-scout \
    --nats-url tls://n.example:4222 --state-dir "$STATE" --config-dir "$CONFIG" --container-name test-scout)
assert_exit "nats-tls/verify-only接受" 0 "$rc"

printf '\n通过 %d，失败 %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
