FROM rust:1.94.1-bookworm AS rust
FROM ghcr.io/foundry-rs/foundry:v1.8.6 AS foundry
FROM node:26.7.0-bookworm
COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=foundry /usr/local/bin/forge /usr/local/bin/anvil /usr/local/bin/cast /usr/local/bin/
ENV CARGO_HOME=/usr/local/cargo RUSTUP_HOME=/usr/local/rustup
ENV PATH=/usr/local/cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends zstd python3 python3-venv && rm -rf /var/lib/apt/lists/*
RUN cargo install just --version 1.58.0 --locked
ARG ARTIFACT_REVISION=unknown
ENV ARTIFACT_REVISION=$ARTIFACT_REVISION
WORKDIR /artifact
COPY offchain/package.json offchain/package-lock.json ./offchain/
RUN npm --prefix offchain ci
COPY . .
RUN bash scripts/install-contract-deps.sh && bash scripts/evaluation.sh --setup && just build
ENTRYPOINT ["just"]
CMD ["reproduce"]
