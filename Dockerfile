# syntax=docker/dockerfile:1
#
# Static musl build of apigw in a distroless image. cargo-chef caches
# dependency compilation, so only the workspace crates recompile on source changes.

# Keep this Rust version in sync with rust-toolchain.toml.
FROM rust:1.98.1-alpine AS chef
# aws-lc-rs compiles C on musl: cmake/make/clang/perl and musl/linux headers.
RUN apk add --no-cache musl-dev pkgconfig cmake make perl clang linux-headers \
    && cargo install cargo-chef --locked
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG SOURCE_DATE_EPOCH=0
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --package apigw --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN touch -d "@${SOURCE_DATE_EPOCH}" crates/apigw/src/main.rs \
    && cargo build --release --locked --package apigw \
    && mkdir -p /var/cache/apigw

# distroless/static ships the CA bundle that reqwest's platform verifier needs
# for HTTPS integrations.
FROM gcr.io/distroless/static-debian13:nonroot
LABEL org.opencontainers.image.source=https://github.com/smoketurner/amazon-apigateway-self-hosted
COPY --from=builder /app/target/release/apigw /apigw
COPY --from=builder --chown=nonroot:nonroot /var/cache/apigw /var/cache/apigw
ENV APIGW_LISTEN=0.0.0.0:8443 \
    APIGW_ADMIN_LISTEN=0.0.0.0:9443 \
    APIGW_CONFIG_CACHE=/var/cache/apigw/config.json
EXPOSE 8443 9443
ENTRYPOINT ["/apigw"]
