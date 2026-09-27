#
# Dockerfile for phantun
#

#
# Build stage
#
FROM rust:latest AS builder

WORKDIR /usr/src/phantun
COPY . .

# Strip debug symbols from release binaries
ENV CARGO_PROFILE_RELEASE_STRIP=true

RUN cargo build --release

#
# Runtime stage
#
FROM debian:stable-slim

RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/phantun/target/release/client /usr/local/bin/phantun-client
COPY --from=builder /usr/src/phantun/target/release/server /usr/local/bin/phantun-server
COPY docker/phantun.sh /usr/local/bin/

ENV USE_IPTABLES_NFT_BACKEND=1
ENV RUST_LOG=info

ENTRYPOINT ["phantun.sh"]
CMD ["phantun-server", "--help"]
