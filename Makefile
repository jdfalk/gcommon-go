# file: Makefile
# version: 2.1.0
# guid: makefile-gcommon-go-automation

.PHONY: help setup build test clean generate install-tools release-patch release-minor release-major

help: ## Show this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: install-tools ## Set up development environment
	go mod download
	go mod tidy

install-tools: ## Install required tools
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	go install github.com/bufbuild/buf/cmd/buf@latest

generate: ## Generate Go code from protocol buffers using BSR (managed mode)
	@echo "📡 Generating Go code from buf.build/jdfalk/gcommon using managed mode..."
	buf generate
	@echo "🔧 Fixing Go module paths for v1/v2+ compatibility..."
	python3 scripts/fix-go-paths.py

build: generate ## Build the Go module
	go build ./...

test: generate ## Run tests
	go test -v ./...

clean: ## Clean generated files
	find . -name "*.pb.go" -type f -delete
	find . -name "*_grpc.pb.go" -type f -delete

lint: ## Run linters
	golangci-lint run

doc: ## Generate documentation
	godoc -http=:6060

fix-paths: ## Run the Go path fixing script manually
	@echo "🔧 Running Go path fixes..."
	python3 scripts/fix-go-paths.py

release-patch: ## Create a patch release (x.y.Z)
	@echo "🚀 Creating patch release..."
	python3 scripts/release-manager.py patch

release-minor: ## Create a minor release (x.Y.0)
	@echo "🚀 Creating minor release..."
	python3 scripts/release-manager.py minor

release-major: ## Create a major release (X.0.0)
	@echo "🚀 Creating major release..."
	python3 scripts/release-manager.py major

.DEFAULT_GOAL := help
