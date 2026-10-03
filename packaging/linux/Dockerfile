# The tools that build the Linux package of the desktop app. Linux is built
# but not verified: no Linux desktop has run what this makes. See
# docs/release.md.
#
# Ubuntu 22.04, so that the package needs no newer system libraries than
# 22.04 has (glibc 2.35, WebKitGTK 4.1).
FROM ubuntu:22.04

ARG RUST_VERSION=1.95.0
ARG NODE_VERSION=24.21.0
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl file git pkg-config xz-utils \
      libssl-dev libwebkit2gtk-4.1-dev libxdo-dev libayatana-appindicator3-dev librsvg2-dev \
 && rm -rf /var/lib/apt/lists/*

# Node from its official release, checked against the published sums.
RUN case "$TARGETARCH" in amd64) arch=x64 ;; arm64) arch=arm64 ;; *) echo "unknown $TARGETARCH" >&2; exit 1 ;; esac \
 && name="node-v$NODE_VERSION-linux-$arch.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v$NODE_VERSION/$name" \
 && curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt" | grep " $name\$" | sha256sum -c - \
 && tar -xJf "$name" -C /usr/local --strip-components=1 \
 && rm "$name"

# The same Rust as the project's other builds.
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST_VERSION"
ENV PATH=/root/.cargo/bin:$PATH \
    CARGO_INCREMENTAL=0

WORKDIR /src
# The source arrives as an archive of one commit; the package is built from
# it with the lockfiles as they are.
CMD ["sh", "-c", "cd apps/desktop && npm ci --no-audit --no-fund && npm run tauri:build -- --bundles deb"]
