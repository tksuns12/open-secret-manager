# The tools that build the Linux package of the desktop app. Linux is built
# but not verified: no Linux desktop has run what this makes. See
# docs/release.md.
#
# Ubuntu 22.04, so that the package needs no newer system libraries than
# 22.04 has (glibc 2.35, WebKitGTK 4.1).
FROM ubuntu:22.04@sha256:b000e69a50ff940390233025e7a337fb8469b509e2334fa4d018ac30f3e18cdb

ARG RUST_VERSION=1.95.0
ARG NODE_VERSION=24.21.0
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl file git pkg-config xz-utils \
      libssl-dev libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev \
 && rm -rf /var/lib/apt/lists/*

# Node from its official release, verified against pinned per-arch SHA-256 sums.
RUN case "$TARGETARCH" in \
      amd64) arch=x64;   sum=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6 ;; \
      arm64) arch=arm64; sum=6ad1325edbdb5649c379b75a237147a666c95d4f9ae8d340fef2d1575d289ad2 ;; \
      *) echo "unknown $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && name="node-v$NODE_VERSION-linux-$arch.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v$NODE_VERSION/$name" \
 && echo "$sum  $name" | sha256sum -c - \
 && tar -xJf "$name" -C /usr/local --strip-components=1 \
 && rm "$name"

# The same Rust as the project's other builds, installed via pinned rustup-init
# verified against its published SHA-256 sum rather than piping curl to sh.
RUN case "$TARGETARCH" in \
      amd64) triple=x86_64-unknown-linux-gnu;  sum=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;; \
      arm64) triple=aarch64-unknown-linux-gnu; sum=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;; \
      *) echo "unknown $TARGETARCH" >&2; exit 1 ;; \
    esac \
 && cd /tmp \
 && curl -fsSLo rustup-init "https://static.rust-lang.org/rustup/archive/1.29.3/$triple/rustup-init" \
 && echo "$sum  rustup-init" | sha256sum -c - \
 && chmod +x rustup-init \
 && ./rustup-init -y --no-modify-path --profile minimal --default-toolchain "$RUST_VERSION" \
 && rm rustup-init
ENV PATH=/root/.cargo/bin:$PATH \
    CARGO_INCREMENTAL=0

WORKDIR /src
# The source arrives as an archive of one commit; the package is built from
# it with the lockfiles as they are.
CMD ["sh", "-c", "cd apps/desktop && npm ci --no-audit --no-fund && npm run tauri:build -- --bundles deb -- --locked"]
