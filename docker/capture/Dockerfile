# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS rust-builder
WORKDIR /build
RUN apt-get update && apt-get install -y cmake libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release -p netwatcher-shipper && \
    mkdir -p /build/out && \
    cp /build/target/release/netwatcher-shipper /build/out/

FROM zeek/zeek:6.2.1 AS zeek-base

FROM debian:bookworm-slim AS capture

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl supervisor tcpdump iproute2 libjson-c5 libmaxminddb0 libnode108 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=zeek-base /usr/local/zeek /usr/local/zeek
ENV PATH="/usr/local/zeek/bin:${PATH}"

COPY --from=rust-builder /build/out/netwatcher-shipper /usr/local/bin/netwatcher-shipper

COPY docker/capture/scripts/ /opt/netwatcher/scripts/
COPY docker/capture/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/capture/zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek

RUN chmod +x /opt/netwatcher/scripts/*.sh \
    && mkdir -p /logs/zeek /pcap /var/log/supervisor /var/run

ENV CAPTURE_INTERFACE=auto
ENV GATEWAY_URL=http://gateway:8080
ENV AGENT_ID=capture-agent-1
ENV ZEEK_LOG_PATH=/logs/zeek
ENV PCAP_DIR=/pcap
ENV PCAP_ROTATE_SECS=30
ENV PCAP_ROTATE_COUNT=20
ENV PCAP_ROTATE_SIZE_MB=10

VOLUME ["/logs", "/pcap"]

ENTRYPOINT ["/opt/netwatcher/scripts/entrypoint.sh"]
