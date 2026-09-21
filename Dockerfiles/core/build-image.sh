#!/usr/bin/env bash
#
# 构建自建的 billionmail/core 镜像，用于替换 docker-compose.yml 里的官方镜像。
#
# Dockerfile 的 COPY 路径同时引用了 core/<子目录> 和与自身平级的 core.sh 等脚本，
# 仓库里不存在同时满足两者的目录，因此这里先把两部分汇到一个临时构建上下文再 build。
#
# 用法：
#   ./Dockerfiles/core/build-image.sh                          # 默认打 tag billionmail/core:local
#   ./Dockerfiles/core/build-image.sh billionmail/core:4.9.3-safepath
#   TARGETARCH=arm64 ./Dockerfiles/core/build-image.sh         # 交叉构建 arm64
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TAG="${1:-billionmail/core:local}"
TARGETARCH="${TARGETARCH:-amd64}"

# 与官方发行版一致的编译参数：strip 符号表并去掉构建路径
GO_BUILD_FLAGS=(-trimpath -ldflags=-s\ -w -o "billionmail-${TARGETARCH}" .)

if command -v go >/dev/null 2>&1; then
    echo "==> 用本机 Go 编译 linux/${TARGETARCH} 二进制"
    (
        cd "$REPO_ROOT/core"
        GOOS=linux GOARCH="$TARGETARCH" CGO_ENABLED=0 go build "${GO_BUILD_FLAGS[@]}"
    )
else
    # 全新服务器通常没有 Go，用容器编译，免去装工具链。
    # 模块缓存放在具名卷里，重复构建不必重新下载依赖。
    echo "==> 本机无 Go，改用 golang 容器编译 linux/${TARGETARCH} 二进制"
    docker run --rm \
        -v "$REPO_ROOT/core:/src" -w /src \
        -v billionmail-gomod-cache:/go/pkg/mod \
        -e GOOS=linux -e GOARCH="$TARGETARCH" -e CGO_ENABLED=0 \
        golang:1.24-alpine \
        go build "${GO_BUILD_FLAGS[@]}"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

echo "==> 组装构建上下文"
mkdir -p "$STAGE/core"
cp "$REPO_ROOT/core/billionmail-${TARGETARCH}" "$STAGE/core/"
for dir in manifest languages public resource template; do
    cp -R "$REPO_ROOT/core/$dir" "$STAGE/core/$dir"
done
for file in Dockerfile core.sh stop-supervisor.sh restart_fail2ban.sh supervisord.conf fail2ban.conf; do
    cp "$REPO_ROOT/Dockerfiles/core/$file" "$STAGE/$file"
done

echo "==> docker build -t ${TAG}"
docker build \
    --platform "linux/${TARGETARCH}" \
    --build-arg "TARGETARCH=${TARGETARCH}" \
    -t "$TAG" \
    "$STAGE"

echo "==> 完成：${TAG}"
echo "    接下来把 docker-compose.yml 中 core-billionmail 的 image 改成该 tag，"
echo "    再执行：docker compose up -d core-billionmail"
