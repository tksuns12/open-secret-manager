# The tools that build the Android release, as F-Droid's build server has
# them: x86_64 Debian 12 with its OpenJDK 17, the Android SDK, and the Rust
# and NDK that apps/mobile/android/prepare-release.sh names. A release is
# built here, never on a Mac: Cargo puts the kind of machine that builds
# into every crate's hash, and so into the order of the shared code's
# functions, and F-Droid compares what its own server builds with the APK
# the project signed. scripts/release-android.sh builds the image and signs
# what comes out. See docs/release.md.
FROM debian:bookworm@sha256:1d04200c2ece1d4d75a2a6f8e11ebce7d86a2ae28b34bb2c9cbb3ee9f4953e75

# Passed in by scripts/release-android.sh, from prepare-release.sh.
ARG RUST_VERSION
ARG NDK_VERSION

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git openjdk-17-jdk-headless unzip \
 && rm -rf /var/lib/apt/lists/*

# The Android SDK's command-line tools, platform, build-tools, and NDK, each
# pinned by direct archive URL and verified with SHA-256 (cross-checked against
# https://dl.google.com/android/repository/repository2-3.xml).
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" "$ANDROID_HOME/platforms" "$ANDROID_HOME/build-tools" "$ANDROID_HOME/ndk" \
 && cd /tmp \
 && curl -fsSLo tools.zip https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip \
 && echo "0877a1d048fe4a24efe2eff536ca4223f7adeb58648bb81909d33c446918cfa8  tools.zip" | sha256sum -c - \
 && unzip -q tools.zip && mv cmdline-tools "$ANDROID_HOME/cmdline-tools/latest" && rm tools.zip \
 && curl -fsSLo platform-36.zip https://dl.google.com/android/repository/platform-36_r02.zip \
 && echo "37607369a28c5b640b3a7998868d45898ebcb777565a0e85f9acf36f29631d2e  platform-36.zip" | sha256sum -c - \
 && unzip -q platform-36.zip && mv android-36 "$ANDROID_HOME/platforms/android-36" && rm platform-36.zip \
 && curl -fsSLo build-tools-35.zip https://dl.google.com/android/repository/build-tools_r35_linux.zip \
 && echo "bd3a4966912eb8b30ed0d00b0cda6b6543b949d5ffe00bea54c04c81e1561d88  build-tools-35.zip" | sha256sum -c - \
 && unzip -q build-tools-35.zip && mv android-15 "$ANDROID_HOME/build-tools/35.0.0" && rm build-tools-35.zip \
 && (yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true) \
 && test "$NDK_VERSION" = 30.0.16248370 \
 && curl -fsSLo ndk.zip https://dl.google.com/android/repository/android-ndk-r30-linux.zip \
 && echo "753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2  ndk.zip" | sha256sum -c - \
 && unzip -q ndk.zip && mv android-ndk-r30 "$ANDROID_HOME/ndk/$NDK_VERSION" && rm ndk.zip
ENV ANDROID_NDK_HOME=$ANDROID_HOME/ndk/$NDK_VERSION

# Rust through rustup, its installer checked against its published sum.
RUN cd /tmp \
 && curl -fsSLo rustup-init https://static.rust-lang.org/rustup/archive/1.29.3/x86_64-unknown-linux-gnu/rustup-init \
 && echo "b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55  rustup-init" | sha256sum -c - \
 && chmod +x rustup-init \
 && ./rustup-init -y --no-modify-path --profile minimal --target aarch64-linux-android \
      --default-toolchain "$RUST_VERSION" \
 && rm rustup-init
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /src
# The source arrives as an archive of one commit.
CMD ["sh", "-c", "apps/mobile/android/prepare-release.sh && cd apps/mobile/android && ./gradlew --no-daemon --no-watch-fs --quiet --no-build-cache --dependency-verification=strict :app:assembleRelease"]
