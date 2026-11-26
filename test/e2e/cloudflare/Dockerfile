# Cloudflare's verifiers, built from crates.io: wba-verify checks a request's
# signature, http-signature-directory checks the key directory.
ARG RUST_IMAGE
FROM ${RUST_IMAGE}
WORKDIR /src
# One target directory, so the dependencies both share compile once; the
# crates.io tool first, so a change to wba-verify doesn't rebuild it.
ENV CARGO_TARGET_DIR=/tmp/target
RUN cargo install --locked --root /usr/local http-signature-directory@0.8.0
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo install --locked --root /usr/local --path . && \
    rm -rf /tmp/target "${CARGO_HOME:-/usr/local/cargo}/registry"
ENTRYPOINT []
