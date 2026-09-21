#!/usr/bin/env bash
#
# 把运行中的 core 容器替换成由本仓库源码构建的版本（含 SafePath 公共路由修复）。
#
# 用法：在 BillionMail 部署目录下，执行完官方 install.sh 之后运行一次
#   ./apply-core-patch.sh
#   TAG=billionmail/core:mine ./apply-core-patch.sh     # 自定义 tag
#
# 为什么镜像 tag 写在 docker-compose.override.yml 而不是 docker-compose.yml：
# bm.sh update 会备份并覆盖 docker-compose.yml（见 bm.sh 的 update 流程），
# 改在那里每次升级都会被冲掉；override 文件它不碰，docker compose 会自动合并。
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

TAG="${TAG:-billionmail/core:patched}"
OVERRIDE="docker-compose.override.yml"

if [ ! -f docker-compose.yml ]; then
    echo "错误：当前目录没有 docker-compose.yml，不是 BillionMail 部署目录" >&2
    exit 1
fi

echo "==> 构建镜像 ${TAG}"
./Dockerfiles/core/build-image.sh "$TAG"

echo "==> 写入 ${OVERRIDE}"
cat > "$OVERRIDE" <<EOF
# 由 apply-core-patch.sh 生成，请勿手工编辑。
# 将 core 指向本仓库源码构建的镜像；pull_policy: never 可避免
# docker compose pull 去远端找这个只存在于本机的 tag。
services:
  core-billionmail:
    image: ${TAG}
    pull_policy: never
EOF

echo "==> 校验 compose 配置"
docker compose config --quiet

echo "==> 重建 core 容器"
docker compose up -d core-billionmail

echo "==> 当前状态"
docker compose ps core-billionmail
echo
echo "完成。验证（应为 200 / 404）："
echo "  curl -sk -o /dev/null -w '%{http_code}\\n' https://127.0.0.1/roundcube"
echo "  curl -sk -o /dev/null -w '%{http_code}\\n' https://127.0.0.1/overview"
