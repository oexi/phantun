# syntax=docker/dockerfile:1

#
# Dockerfile for phantun
#

#
# Build stage
#
# Keep the builder and runtime on the same Debian release so the
# binaries never link against a newer glibc than the runtime provides.
FROM rust:1-trixie AS builder

WORKDIR /usr/src/phantun
COPY . .

ENV CARGO_PROFILE_RELEASE_STRIP=true
ENV CARGO_PROFILE_RELEASE_LTO=true
ENV CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1

# target/ lives in a cache mount, so copy the binaries out in the same step
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/usr/src/phantun/target \
    cargo build --release --locked \
    && install target/release/server /usr/local/bin/phantun-server \
    && install target/release/client /usr/local/bin/phantun-client

#
# Runtime stage
#
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    iptables \
    iproute2 \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/phantun-server /usr/local/bin/phantun-client /usr/local/libexec/phantun/
COPY docker/phantun.sh /usr/local/bin/
# The commands run phantun.sh, so the sysctls and iptables rules are also set up when a runtime
# such as RouterOS runs the command directly rather than through the entrypoint
RUN ln -s phantun.sh /usr/local/bin/phantun-server \
    && ln -s phantun.sh /usr/local/bin/phantun-client

ENV RUST_LOG=info

ENTRYPOINT ["phantun.sh"]
CMD ["phantun-server", "--help"]
