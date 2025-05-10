# Stage 1: Build static binaries using Rust MUSL target
# 构建阶段
FROM rust:1.84.1-alpine AS builder

# 设置构建环境 (静态链接)
ENV RUSTFLAGS="-C target-feature=+crt-static"

# 安装必要的构建依赖 (Alpine)
RUN apk add --no-cache \
    build-base \
    openssl-dev \
    openssl-libs-static \
    musl-dev \
    pkgconfig \
    cmake \
    git

# 设置工作目录
WORKDIR /build

# 复制项目文件
COPY . .

# 安装 MUSL target
RUN rustup target add x86_64-unknown-linux-musl

# 构建静态 Server 二进制
RUN cargo build --bin owdns --target x86_64-unknown-linux-musl --release

# 构建静态 Client 二进制
RUN cargo build --bin owdns-cli --target x86_64-unknown-linux-musl --release


# Stage 2: Create final minimal image
# 使用 alpine 作为基础镜像。可以考虑换成 gcr.io/distroless/static-debian11 以获得更小的镜像尺寸和更高的安全性，
# 但 alpine 包含 shell，可能便于调试。
FROM alpine:3.19

# 设置时区为上海 (可选)
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

# 创建工作目录
WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/owdns /app/owdns
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/owdns-cli /app/owdns-cli

# 复制默认配置文件
# COPY config.default.yaml /app/config.yaml

# 设置运行用户 (保持不变)
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# (可选) 暴露端口 (如果 owdns 监听端口)
EXPOSE 3053

# 默认运行服务端程序。
# 客户端可以通过 `docker exec <container_id> /app/owdns-cli ...` 来运行。
# 假设服务端需要一个配置文件
ENTRYPOINT ["/app/owdns"]