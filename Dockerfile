# syntax=docker/dockerfile:1

# Sentinel 镜像构建（多阶段）
#
# 目标（target）：
#   hub   —— 服务端，内嵌前端静态资源（web/dist 在容器内构建，不依赖宿主 Node）
#   scout —— 主机 Agent，特权容器运行，宿主数据通过 /host 只读挂载提供
#
# 构建：
#   docker build --target hub   -t sentinel-hub:dev .
#   docker build --target scout -t sentinel-scout:dev .
# 多架构（发布，需 buildx + QEMU）：
#   docker buildx build --platform linux/amd64,linux/arm64 --target scout -t <ref> --push .
#
# 说明：
# - 构建与运行统一基于 bookworm，保证 glibc 一致；工具链固定 1.97.1
#   （rust-toolchain.toml 一并复制进构建阶段，与本地开发一致）。
# - migrations/ 复制进 Rust 构建阶段：hub 使用 SQLx 编译期内嵌迁移（build.rs 声明
#   rerun-if-changed），运行镜像不再携带迁移文件。
# - scout 以 root 运行（需读取宿主 /proc、/etc 等文件，属宿主机级可信组件，见
#   docs/architecture.md 的 Scout 容器部署章节）；hub 以非特权用户运行。
# - scout 镜像不挂载 Docker socket（本批不需要，见 docs/implementation-contract.md）。

ARG RUST_IMAGE=rust:1.97.1-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=debian:bookworm-slim

# ---------------------------------------------------------------------------
# 阶段 1：Rust 构建（hub / scout 两个二进制，迁移编译期内嵌）
# ---------------------------------------------------------------------------
FROM ${RUST_IMAGE} AS cargo-build
# 多架构构建时按平台隔离 target 缓存：跨平台共用同一缓存路径会互相覆盖产物
ARG TARGETARCH
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY migrations/ migrations/
COPY crates/ crates/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=sentinel-target-${TARGETARCH:-native},target=/src/target,sharing=locked \
    cargo build --release --locked --bin hub --bin scout \
    && mkdir -p /out \
    && cp target/release/hub target/release/scout /out/

# ---------------------------------------------------------------------------
# 阶段 2：前端构建（Vue 3 + TypeScript + Vite，输出 dist）
# ---------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS web-build
WORKDIR /src
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run --if-present type-check \
    && npm run build

# ---------------------------------------------------------------------------
# 目标：hub（服务端）
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS hub
LABEL org.opencontainers.image.source="https://github.com/J1a-wei/Sentinel" \
      org.opencontainers.image.description="Sentinel Hub server (development stage)"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /app sentinel
WORKDIR /app
COPY --from=cargo-build /out/hub /usr/local/bin/hub
COPY --from=web-build /src/dist /app/web/dist
# 容器内显式绑定 0.0.0.0；宿主端口仅在部署编排中映射到 loopback（见 deploy/）。
# 凭证通过 *_FILE 注入（挂载文件）；部署编排需以可读取 0600 凭证文件的
# UID/GID 运行容器（compose 用 user: 指定，见 docs/deployment.md）。
ENV SENTINEL_WEB_DIR=/app/web/dist \
    SENTINEL_BIND=0.0.0.0:8080
USER sentinel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["hub", "health"]
ENTRYPOINT ["/usr/local/bin/hub"]

# ---------------------------------------------------------------------------
# 目标：scout（主机 Agent）
# ---------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS scout
LABEL org.opencontainers.image.source="https://github.com/J1a-wei/Sentinel" \
      org.opencontainers.image.description="Sentinel Scout agent (development stage)"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=cargo-build /out/scout /usr/local/bin/scout
# 宿主数据由部署编排挂载到 /host（/proc、/sys、/etc、dpkg 数据库、os-release），
# 状态目录为 /var/lib/sentinel；本镜像不假设这些路径在构建时存在。
ENV SENTINEL_HOST_ROOT=/host \
    SENTINEL_STATE_DIR=/var/lib/sentinel
ENTRYPOINT ["/usr/local/bin/scout"]
