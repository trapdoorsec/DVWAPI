# DVWAPI Makefile

# Docker configuration
DOCKER_REPO ?= trapdoorsec/dvwapi
TAG ?= latest
VERSION := $(shell grep '^version' Cargo.toml | cut -d'"' -f2)

# Build variables
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

.PHONY: help
help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-20s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the Docker image locally
	docker build \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_REPO):$(TAG) \
		-t $(DOCKER_REPO):$(VERSION) \
		-t $(DOCKER_REPO):latest \
		.

.PHONY: build-no-cache
build-no-cache: ## Build the Docker image without cache
	docker build --no-cache \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		-t $(DOCKER_REPO):$(TAG) \
		-t $(DOCKER_REPO):$(VERSION) \
		-t $(DOCKER_REPO):latest \
		.

.PHONY: run
run: ## Run the container locally
	docker run -d \
		--name dvwapi \
		-p 7341:7341 \
		$(DOCKER_REPO):$(TAG)

.PHONY: run-interactive
run-interactive: ## Run the container interactively
	docker run -it --rm \
		-p 7341:7341 \
		$(DOCKER_REPO):$(TAG)

.PHONY: stop
stop: ## Stop the running container
	docker stop dvwapi || true
	docker rm dvwapi || true

.PHONY: logs
logs: ## Show container logs
	docker logs -f dvwapi

.PHONY: shell
shell: ## Open a shell in the running container
	docker exec -it dvwapi /bin/bash

.PHONY: push
push: ## Push image to Docker Hub
	docker push $(DOCKER_REPO):$(VERSION)
	docker push $(DOCKER_REPO):$(TAG)
	docker push $(DOCKER_REPO):latest

.PHONY: tag-version
tag-version: ## Tag the current commit with version from Cargo.toml
	git tag -a v$(VERSION) -m "Release v$(VERSION)"
	git push origin v$(VERSION)

.PHONY: login
login: ## Login to Docker Hub
	docker login

.PHONY: publish
publish: build push tag-version ## Build, push to Docker Hub, and tag git commit

.PHONY: test-local
test-local: build run ## Build and run locally for testing
	@echo "Waiting for container to start..."
	@sleep 3
	@echo "Testing endpoints..."
	@curl -s http://localhost:7341/ | jq . || echo "Container is starting..."

.PHONY: clean
clean: stop ## Clean up containers and images
	docker rmi $(DOCKER_REPO):$(TAG) || true
	docker rmi $(DOCKER_REPO):$(VERSION) || true
	docker rmi $(DOCKER_REPO):latest || true

.PHONY: compose-up
compose-up: ## Start services using docker-compose
	docker-compose up -d

.PHONY: compose-down
compose-down: ## Stop services using docker-compose
	docker-compose down

.PHONY: compose-logs
compose-logs: ## Show docker-compose logs
	docker-compose logs -f

.PHONY: cargo-build
cargo-build: ## Build the Rust application natively
	cargo build --release

.PHONY: cargo-test
cargo-test: ## Run Rust tests
	cargo test

.PHONY: cargo-clean
cargo-clean: ## Clean Rust build artifacts
	cargo clean

.PHONY: all
all: cargo-test build ## Run tests and build Docker image
