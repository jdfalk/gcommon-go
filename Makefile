# file: Makefile
# version: 2.0.0
# guid: makefile-gcommon-go-automation

.PHONY: help setup build test clean generate install-tools test-managed switch-managed switch-regular

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

generate: ## Generate Go code from protocol buffers using BSR
	@echo "📡 Generating Go code from buf.build/jdfalk/gcommon..."
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

switch-managed: ## Switch to managed mode buf.gen.yaml for testing
	@echo "🔄 Switching to managed mode generation..."
	@if [ -f buf.gen.yaml ]; then mv buf.gen.yaml buf.gen.regular.yaml; fi
	@if [ -f buf.gen.managed.yaml ]; then cp buf.gen.managed.yaml buf.gen.yaml; fi
	@echo "✅ Switched to managed mode (buf.gen.managed.yaml)"

switch-regular: ## Switch back to regular buf.gen.yaml
	@echo "🔄 Switching to regular mode generation..."
	@if [ -f buf.gen.regular.yaml ]; then mv buf.gen.regular.yaml buf.gen.yaml; fi
	@echo "✅ Switched to regular mode (buf.gen.yaml)"

test-managed: switch-managed generate switch-regular ## Test managed mode generation
	@echo "🧪 Testing managed mode generation complete"

fix-paths: ## Run the Go path fixing script manually
	@echo "🔧 Running Go path fixes..."
	python3 scripts/fix-go-paths.py

.DEFAULT_GOAL := help
