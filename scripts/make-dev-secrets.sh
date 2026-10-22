#!/usr/bin/env bash
#
# 生成 Sentinel 开发环境 secrets（deploy/secrets/，目录已被 .gitignore 忽略）。
#
# 产出（均为 0600，属主为当前用户；hub 容器需以相同 UID/GID 运行，见
# deploy/compose/.env.example 的 HUB_UID/HUB_GID）：
#   admin-token       Hub 管理员令牌（SENTINEL_ADMIN_TOKEN，>= 32 字符）
#   nats-client-token NATS 客户端 token
#   nats-server.conf  nats-server 配置（内嵌 token、JetStream 与监控端口）
#
# 仅供本机 loopback 开发环境；跨机部署必须另行提供 TLS 与正式凭证管理。

set -euo pipefail

usage() {
    cat <<'EOF'
用法：make-dev-secrets.sh [--dir DIR] [--force]
  --dir DIR   输出目录（默认 <仓库>/deploy/secrets）
  --force     覆盖已存在的文件（默认拒绝）。仅轮换开发管理/NATS凭证，
              不影响 var/scout 中的本地安装身份
EOF
}

die() {
    printf '错误：%s\n' "$*" >&2
    exit 1
}

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/deploy/secrets"
FORCE="false"

while [ $# -gt 0 ]; do
    case "$1" in
        --dir)
            [ $# -ge 2 ] || die "--dir 需要参数"
            DIR=$2
            shift 2
            ;;
        --force)
            FORCE="true"
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        *)
            die "未知参数：$1"
            ;;
    esac
done

command -v openssl >/dev/null 2>&1 || die "需要 openssl 生成随机值"

for f in admin-token nats-client-token nats-server.conf; do
    if [ -e "${DIR}/${f}" ] && [ "$FORCE" != "true" ]; then
        die "${DIR}/${f} 已存在。确认覆盖请加 --force（会轮换开发凭证，Hub/Scout 侧需同步更新）"
    fi
done

mkdir -p "$DIR"
umask 077

ADMIN_TOKEN=$(openssl rand -hex 32)
NATS_TOKEN=$(openssl rand -hex 16)

printf '%s\n' "$ADMIN_TOKEN" >"${DIR}/admin-token"
printf '%s\n' "$NATS_TOKEN" >"${DIR}/nats-client-token"
cat >"${DIR}/nats-server.conf" <<EOF
# 由 scripts/make-dev-secrets.sh 生成（0600）；仅限本机 loopback 开发环境
listen: 0.0.0.0:4222
http: 8222

authorization {
    token: "${NATS_TOKEN}"
}

jetstream {
    store_dir: /data
}
EOF

chmod 600 "${DIR}/admin-token" "${DIR}/nats-client-token" "${DIR}/nats-server.conf"

printf '已生成（0600）：\n  %s/admin-token\n  %s/nats-client-token\n  %s/nats-server.conf\n' "$DIR" "$DIR" "$DIR"
printf '提示：\n'
# shellcheck disable=SC2016  # 提示文案中的 $(id -u)/$(id -g) 是要展示给用户看的字面命令
printf '  1. 在 deploy/compose/.env 中设置 POSTGRES_PASSWORD，并令 HUB_UID=$(id -u) HUB_GID=$(id -g)\n'
printf '  2. admin-token 即 UI/API 登录令牌（SENTINEL_ADMIN_TOKEN），请勿提交或写入日志\n'
printf '  3. 这些值仅用于开发环境；--force 重新生成仅轮换开发管理/NATS凭证，不会作废 var/scout 中的本地 Ed25519 安装身份\n'
