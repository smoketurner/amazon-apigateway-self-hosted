# syntax=docker/dockerfile:1
#
# Static musl build of apigw in a distroless image. cargo-chef caches
# dependency compilation, so only the workspace crates recompile on source changes.

# Keep this Rust version in sync with rust-toolchain.toml.
FROM rust:1.100.0-alpine@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS chef
# aws-lc-rs compiles C on musl: cmake/make/clang/perl and musl/linux headers.
RUN apk add --no-cache musl-dev pkgconfig cmake make perl clang linux-headers \
    && cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /app

FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
ARG SOURCE_DATE_EPOCH=0
# Reported by the apigw_build_info metric.
ARG APIGW_GIT_COMMIT=""
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked --package apigw --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN touch -d "@${SOURCE_DATE_EPOCH}" crates/apigw/src/main.rs \
    && APIGW_GIT_COMMIT="${APIGW_GIT_COMMIT}" cargo build --release --locked --package apigw \
    && mkdir -p /var/cache/apigw

# distroless/static ships the CA bundle that reqwest's platform verifier needs
# for HTTPS integrations.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931
LABEL org.opencontainers.image.source=https://github.com/smoketurner/amazon-apigateway-self-hosted
COPY --from=builder /app/target/release/apigw /apigw
COPY --from=builder --chown=nonroot:nonroot /var/cache/apigw /var/cache/apigw
# No APIGW_CONFIG_CACHE default: --domain-name rejects a cache, and a variable
# set here cannot be unset by a pod spec. /var/cache/apigw is there to point it at.
ENV APIGW_LISTEN=0.0.0.0:8443 \
    APIGW_ADMIN_LISTEN=0.0.0.0:9443
EXPOSE 8443 9443
ENTRYPOINT ["/apigw"]
