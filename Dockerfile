# ── Stage 1: Build static musl binary ────────────────────────────────────────
FROM rust:1.99.1-alpine AS builder

# musl-dev provides the musl libc headers; linux-headers provides kernel
# headers needed for AF_PACKET / raw socket support (fingerprint.rs, syn/).
RUN apk add --no-cache musl-dev linux-headers

WORKDIR /build

# Copy only dependency manifests first to leverage Docker layer caching.
COPY Cargo.toml Cargo.lock ./

# Create a dummy main so `cargo build` can resolve all deps without full source.
RUN mkdir -p src/bin && \
    echo 'fn main() {}' > src/main.rs && \
    echo 'fn main() {}' > src/bin/gen_man.rs && \
    rustup target add x86_64-unknown-linux-musl && \
    cargo build --release --locked --target x86_64-unknown-linux-musl 2>&1 || true && \
    rm -f target/x86_64-unknown-linux-musl/release/deps/rayscan* \
           target/x86_64-unknown-linux-musl/release/deps/gen_man*

# Now copy the full source and build the real binary.
COPY src ./src
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

# ── Stage 2: Minimal scratch image ───────────────────────────────────────────
FROM scratch

LABEL org.opencontainers.image.title="rayscan"
LABEL org.opencontainers.image.description="Accuracy-first TCP/UDP port scanner"
LABEL org.opencontainers.image.licenses="MIT"

COPY --from=builder \
    /build/target/x86_64-unknown-linux-musl/release/rayscan \
    /rayscan

ENTRYPOINT ["/rayscan"]

