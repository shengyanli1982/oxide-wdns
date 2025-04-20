# 构建阶段
FROM rust:1.84.1-alpine AS builder

# 设置构建环境
ENV RUSTFLAGS="-C target-feature=+crt-static"

# 安装必要的构建依赖
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

# 安装特定的目标
RUN rustup target add x86_64-unknown-linux-musl

# 构建项目
RUN cargo build --target x86_64-unknown-linux-musl --release

# 运行阶段
FROM alpine:3.19

# 设置时区为上海
RUN apk add --no-cache tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

# 创建工作目录
WORKDIR /app

# 从构建阶段复制编译好的二进制文件
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/owdns /app/

# 设置运行用户
RUN adduser -D -u 1000 appuser && \
    chown -R appuser:appuser /app
USER appuser

# 运行程序
CMD ["./owdns"] 