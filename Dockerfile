# syntax=docker/dockerfile:1

# ---- build the static scanner binary ----
FROM rust:1-slim-trixie AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p msscan && cp target/release/msscan /msscan

# ---- runtime: the binary only ----
FROM debian:trixie-slim AS runtime
RUN useradd --create-home --uid 1000 msscan
COPY --from=builder /msscan /usr/local/bin/msscan
USER msscan
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["msscan", "--version"]
ENTRYPOINT ["msscan"]
CMD ["serve", "--addr", "0.0.0.0:8080"]
