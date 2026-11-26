# Cloudflare's verifiers, built from crates.io: wba-verify checks a request's
# signature, http-signature-directory checks the key directory.
ARG RUST_IMAGE
FROM ${RUST_IMAGE}
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --locked --root /usr/local http-signature-directory@0.8.0 && \
    cargo install --locked --root /usr/local --path . && \
    rm -rf /src/target "${CARGO_HOME:-/usr/local/cargo}/registry"
ENTRYPOINT []
