# syntax=docker/dockerfile:1

FROM rust:1.88-bookworm AS rust-builder
WORKDIR /build
RUN apt-get update && apt-get install -y cmake libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY crates ./crates
RUN cargo build --release -p netwatcher-shipper

FROM zeek/zeek:6.2.1 AS zeek-base

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl git python3 python3-pip supervisor tshark \
    libjson-c5 libmaxminddb0 libpcap0.8 libpcap-dev build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY --from=zeek-base /usr/local/zeek /usr/local/zeek
ENV PATH="/usr/local/zeek/bin:${PATH}"

RUN git clone --depth 1 https://github.com/p0f/p0f.git /opt/p0f \
    && cd /opt/p0f && ./build.sh && install -m 755 p0f /usr/local/bin/p0f

RUN git clone --depth 1 https://github.com/0x4D31/fatt.git /opt/fatt \
    && pip3 install --break-system-packages pyshark

COPY --from=rust-builder /build/target/release/netwatcher-shipper /usr/local/bin/netwatcher-shipper

COPY docker/capture/scripts/ /opt/netwatcher/scripts/
COPY docker/capture/supervisord.conf /etc/supervisor/supervisord.conf
COPY docker/capture/zeek/local.zeek /usr/local/zeek/share/zeek/site/local.zeek

RUN chmod +x /opt/netwatcher/scripts/*.sh \
    && mkdir -p /logs/zeek /logs/p0f /logs/fatt /pcap /var/log/supervisor /var/run

ENV CAPTURE_INTERFACE=eth0
ENV GATEWAY_URL=http://gateway:8080
ENV AGENT_ID=capture-agent-1
ENV ZEEK_LOG_PATH=/logs/zeek

VOLUME ["/logs", "/pcap"]

ENTRYPOINT ["/opt/netwatcher/scripts/entrypoint.sh"]
