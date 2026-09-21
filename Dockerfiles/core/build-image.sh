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

echo "==> 编译 linux/${TARGETARCH} 二进制"
(
    cd "$REPO_ROOT/core"
    GOOS=linux GOARCH="$TARGETARCH" CGO_ENABLED=0 go build -o "billionmail-${TARGETARCH}" .
)

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
