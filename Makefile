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

macos:
	cargo build --release --target x86_64-apple-darwin

armv7:
	@# Use `cross` (recommended). If `cross` is not available, fall back to `cargo` (may fail without a cross toolchain).
	@if command -v cross >/dev/null 2>&1; then \
		cross build --profile minimal --target armv7-unknown-linux-musleabihf; \
	else \
		echo "cross not found: falling back to local cargo (may fail if no toolchain)"; \
		cargo build --release --target armv7-unknown-linux-musleabihf; \
	fi

linux:
	cargo build --release --target x86_64-unknown-linux-musl

bin: macos linux armv7
	@echo Creating tarball...
	@mkdir -p ${TARBALL}
	
	@echo Creating x86_64-apple-darwin
	@tar cvfz "${TARBALL}/${APP_NAME}-${APP_VERSION}-x86_64-apple-darwin.tar.gz" -C target/x86_64-apple-darwin/release/ ${APP_NAME} 

	@echo Creating x86_64-unknown-linux-musl
	@tar cvfz "${TARBALL}/${APP_NAME}-${APP_VERSION}-x86_64-unknown-linux-musl.tar.gz" -C target/x86_64-unknown-linux-musl/release/ ${APP_NAME}

	@echo Creating armv7-unknown-linux-musleabihf
	@tar cvfz "${TARBALL}/${APP_NAME}-${APP_VERSION}-armv7-unknown-linux-musleabihf.tar.gz" -C target/armv7-unknown-linux-musleabihf/release/ ${APP_NAME}

lint:
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
	@PLATFORM=$(PLATFORM); \
	if [ -z "$$PLATFORM" ]; then echo "Usage: make build-for PLATFORM=linux/arm/v7"; exit 1; fi; \
	sh scripts/cross_build.sh "$$PLATFORM"

build-all:
	$(MAKE) build-for PLATFORM=linux/amd64; \
	$(MAKE) build-for PLATFORM=linux/arm/v7; \
	$(MAKE) build-for PLATFORM=linux/arm64

# local build: prebuild binary for the platform then build image
PLATFORM ?= linux/arm/v7
local: build-for
	@echo "Building Docker image for $(PLATFORM)"; \
	docker buildx build --platform $(PLATFORM) --output=type=docker -f docker/Dockerfile.local -t lazywalker/lazydns .; \
	docker save lazywalker/lazydns > lazydns.tar
