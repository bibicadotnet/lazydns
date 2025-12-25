PREFIX=/usr/local
VER=$(shell cargo pkgid | cut -d\# -f2 | cut -d: -f2)
APP_VERSION=${VER}
TARBALL="target/tarball"
APP_NAME="lazydns"
	
all:
	cargo build

clean:
	cargo clean

ver:
	@echo ${APP_NAME} v${APP_VERSION}

release:
	cargo build --release
	
minimal:
	cargo build --profile minimal
	
lint:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo clippy --all-targets --no-default-features -- -D warnings

test:
	cargo test --all-features
	cargo test --no-default-features

cov:
	cargo llvm-cov test -q --all-features

fmt:
	cargo fmt --all

check: lint fmt
	@echo "\033[33mcargo lint and fmt done\033[0m"

# Mapping helper target(s)
.PHONY: build-for build-all

# Build for a single PLATFORM (e.g. PLATFORM=linux/arm/v7)
build-for:
	@PLATFORM=$(PLATFORM); EXTRA=$(EXTRA); \
	if [ -z "$$PLATFORM" ]; then echo "Usage: make build-for PLATFORM=linux/arm/v7 [EXTRA='--no-default-features --features \"log,cron\"']"; exit 1; fi; \
	sh scripts/cross_build.sh "$$PLATFORM" "$$EXTRA"

build-all:
	$(MAKE) build-for PLATFORM=linux/amd64; \
	$(MAKE) build-for PLATFORM=linux/arm/v7; \
	$(MAKE) build-for PLATFORM=linux/arm64

# local build: prebuild binary for the platform then build image
PLATFORM ?= linux/arm/v7
EXTRA ?= "--no-default-features --features log,cron"
local: build-for
	@echo "Building Docker image for $(PLATFORM)"; \
	@echo "Using EXTRA features: $(EXTRA)"; \
	docker buildx build --platform $(PLATFORM) --output=type=docker -f docker/Dockerfile.local.scratch -t lazywalker/lazydns:local .; \
	docker save lazywalker/lazydns:local > lazydns.tar
