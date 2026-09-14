# fn-WireGuard 常用任务入口（实际逻辑在 scripts/ 下）

.PHONY: help version bump release build amd64 arm64 all dev dev-frontend test vet fmt tidy clean

APP_DIR  := apps/fn-wireguard
VERSION  := $(shell sed -n 's/^version[[:space:]]*=[[:space:]]*//p' $(APP_DIR)/manifest | head -1)

help: ## 显示可用命令
	@echo "fn-WireGuard v$(VERSION)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

version: ## 显示当前版本号
	@./scripts/version.sh show

bump: ## 升一个补丁版本（用法: make bump MSG="改动说明"）
	@./scripts/version.sh patch "$(MSG)"

release: ## 升版本号并打包双架构安装包（用法: make release MSG="改动说明"）
	@./scripts/version.sh patch "$(MSG)"
	./scripts/build.sh all

build: ## 编译当前架构的 Linux 二进制（含前端构建与内嵌）
	./scripts/build.sh

amd64: ## 构建并打包 x86_64 安装包
	./scripts/build.sh amd64

arm64: ## 构建并打包 ARM 安装包
	./scripts/build.sh arm64

all: ## 构建并打包双架构安装包
	./scripts/build.sh all

dev: ## 本地开发服务（内存后端，不触碰真实网络）
	./scripts/dev.sh

dev-frontend: ## 前端热更新开发服务器
	./scripts/dev.sh frontend

test: ## 运行全部单元测试（含网络安全回归用例）
	go test ./...

vet: ## 静态检查
	go vet ./...

fmt: ## 格式化 Go 代码
	gofmt -l -w .

tidy: ## 整理 Go 依赖
	go mod tidy

clean: ## 清理构建产物
	rm -rf bin dist frontend/dist internal/webui/dist
	rm -f $(APP_DIR)/app/fnwg-* $(APP_DIR)/app/BUILDINFO
