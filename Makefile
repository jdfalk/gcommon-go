# file: Makefile
# version: 1.0.0
# guid: makefile-gcommon-go-automation

.PHONY: help setup build test clean generate sync-protos install-tools

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

generate: sync-protos ## Generate Go code from protocol buffers
	buf generate

sync-protos: ## Sync protocol buffer definitions from gcommon repo
	@echo "Syncing proto files from gcommon repository..."
	@if [ ! -d "proto" ]; then \
		git clone --depth 1 --no-checkout https://github.com/jdfalk/gcommon.git proto-temp; \
		cd proto-temp && git checkout main -- proto/; \
		mv proto ../proto; \
		cd .. && rm -rf proto-temp; \
	else \
		echo "Proto directory exists, updating..."; \
		cd proto && git pull origin main || (cd .. && rm -rf proto && $(MAKE) sync-protos); \
	fi

build: generate ## Build the Go module
	go build ./...

test: generate ## Run tests
	go test -v ./...

clean: ## Clean generated files
	find . -name "*.pb.go" -type f -delete
	find . -name "*_grpc.pb.go" -type f -delete
	rm -rf proto/

lint: ## Run linters
	golangci-lint run

doc: ## Generate documentation
	godoc -http=:6060

.DEFAULT_GOAL := help
