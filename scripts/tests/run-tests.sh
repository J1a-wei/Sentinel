#!/usr/bin/env bash
#
# scripts/ 交付物测试入口（CI 的 scripts job 调用，也可本地执行）：
#   1. shellcheck（若安装）静态检查全部脚本
#   2. install-scout.sh 的 mock 行为测试
#   3. install-systemd.sh 的 mock 行为测试（嵌入 Python 以 unittest 导入，不触碰真实系统）
#   4. deploy/compose 配置校验（若 docker compose 可用，不启动容器）
#      —— 若本机无 Docker 守护进程权限则跳过并说明，不谎称通过。

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FAIL=0

step() {
    printf '\n== %s ==\n' "$1"
}

if command -v shellcheck >/dev/null 2>&1; then
    step "shellcheck"
    if shellcheck -x "${ROOT}/scripts/install-scout.sh" \
        "${ROOT}/scripts/install-systemd.sh" \
        "${ROOT}/scripts/make-dev-secrets.sh" \
        "${ROOT}/scripts/tests/test-install-scout.sh" \
        "${ROOT}/scripts/tests/run-tests.sh"; then
        echo "shellcheck 通过"
    else
        echo "shellcheck 失败"
        FAIL=1
    fi
else
    echo "跳过 shellcheck：未安装（CI 使用外部 lint 容器或安装后执行）"
fi

step "install-scout.sh mock 测试"
if bash "${ROOT}/scripts/tests/test-install-scout.sh"; then
    echo "mock 测试通过"
else
    echo "mock 测试失败"
    FAIL=1
fi

step "install-systemd.sh mock 测试"
if python3 "${ROOT}/scripts/tests/test-install-systemd.py"; then
    echo "mock 测试通过"
else
    echo "mock 测试失败"
    FAIL=1
fi

step "compose 配置校验"
COMPOSE_FILE="${ROOT}/deploy/compose/docker-compose.dev.yml"
COMPOSE_DIR="${ROOT}/deploy/compose"
if docker compose version >/dev/null 2>&1; then
    # 配置校验需要 secrets 与 .env 存在；用临时文件，不改仓库
    TMPENV="$(mktemp)"
    trap 'rm -f "$TMPENV" "${COMPOSE_DIR}/.env.test-run" 2>/dev/null; rm -rf "${ROOT}/deploy/secrets/.test-run" 2>/dev/null' EXIT
    printf 'POSTGRES_PASSWORD=test-only\nHUB_UID=%s\nHUB_GID=%s\n' "$(id -u)" "$(id -g)" >"$TMPENV"
    mkdir -p "${ROOT}/deploy/secrets/.test-run"
    echo dummy >"${ROOT}/deploy/secrets/.test-run/admin-token"
    echo dummy >"${ROOT}/deploy/secrets/.test-run/nats-client-token"
    {
        echo 'listen: 0.0.0.0:4222'
        echo 'http: 8222'
        echo 'jetstream { store_dir: /data }'
    } >"${ROOT}/deploy/secrets/.test-run/nats-server.conf"
    # compose 文件相对路径基于 compose 文件目录，临时借用 secrets 子目录
    if docker compose --project-directory "$COMPOSE_DIR" --env-file "$TMPENV" \
        -f <(sed "s|../secrets/|../secrets/.test-run/|g" "$COMPOSE_FILE") config >/dev/null 2>&1; then
        echo "compose 配置校验通过（未启动容器）"
    else
        echo "compose 配置校验失败"
        FAIL=1
    fi
    rm -rf "${ROOT}/deploy/secrets/.test-run"
else
    echo "跳过 compose 配置校验：本机无 docker compose（无守护进程权限时 CI 环境会执行）"
fi

printf '\n结论：%s\n' "$([ "$FAIL" -eq 0 ] && echo ALL-PASS || echo FAILED)"
exit "$FAIL"
