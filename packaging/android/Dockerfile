# The tools that build the Android release, as F-Droid's build server has
# them: x86_64 Debian 12 with its OpenJDK 17, the Android SDK, and the Rust
# and NDK that apps/mobile/android/prepare-release.sh names. A release is
# built here, never on a Mac: Cargo puts the kind of machine that builds
# into every crate's hash, and so into the order of the shared code's
# functions, and F-Droid compares what its own server builds with the APK
# the project signed. scripts/release-android.sh builds the image and signs
# what comes out. See docs/release.md.
FROM debian:bookworm

# Passed in by scripts/release-android.sh, from prepare-release.sh.
ARG RUST_VERSION
ARG NDK_VERSION

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git openjdk-17-jdk-headless unzip \
 && rm -rf /var/lib/apt/lists/*

# The Android SDK's command-line tools, the platform and build tools the
# app compiles against, and the NDK, each checked against the SHA-1 Google
# publishes in https://dl.google.com/android/repository/repository2-3.xml.
ENV ANDROID_HOME=/opt/android-sdk
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" "$ANDROID_HOME/ndk" \
 && cd /tmp \
 && curl -fsSLo tools.zip https://dl.google.com/android/repository/commandlinetools-linux-16111833_latest.zip \
 && echo "e025545c62a8e64c7559119566a569fb1dec5f60  tools.zip" | sha1sum -c - \
 && unzip -q tools.zip && mv cmdline-tools "$ANDROID_HOME/cmdline-tools/latest" && rm tools.zip \
 && (yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true) \
 && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" 'platforms;android-36' 'build-tools;35.0.0' >/dev/null \
 && test "$NDK_VERSION" = 30.0.16248370 \
 && curl -fsSLo ndk.zip https://dl.google.com/android/repository/android-ndk-r30-linux.zip \
 && echo "5107f898313790e449e87eee2183d9a20602dee9  ndk.zip" | sha1sum -c - \
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
CMD ["sh", "-c", "apps/mobile/android/prepare-release.sh && cd apps/mobile/android && ./gradlew --no-daemon --no-watch-fs --quiet --no-build-cache :app:assembleRelease"]
