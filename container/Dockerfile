# syntax=docker/dockerfile:1

ARG OQS_BASE=openquantumsafe/oqs-ossl3:latest-x86_64

FROM ${OQS_BASE} AS build

USER root
WORKDIR /src

RUN apk add --no-cache \
    build-base \
    cmake \
    pkgconf \
    nlohmann-json \
    ca-certificates

COPY app/CMakeLists.txt ./
COPY app/include ./include
COPY app/src ./src

RUN test -f /opt/openssl/include/openssl/ssl.h && \
    test -f /opt/openssl/lib64/libssl.so && \
    test -f /opt/openssl/lib64/libcrypto.so && \
    echo "Found OQS/OpenSSL headers and libraries under /opt/openssl"

RUN rm -rf /tmp/build && \
    cmake -S . -B /tmp/build \
      -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=/opt/openssl \
      -DOPENSSL_INCLUDE_DIR=/opt/openssl/include \
      -DOPENSSL_SSL_LIBRARY=/opt/openssl/lib64/libssl.so \
      -DOPENSSL_CRYPTO_LIBRARY=/opt/openssl/lib64/libcrypto.so \
      -DCMAKE_EXE_LINKER_FLAGS="-Wl,-rpath,/opt/openssl/lib64" && \
    cmake --build /tmp/build -j1 && \
    strip /tmp/build/tls_crypto_server

FROM ${OQS_BASE} AS runtime

USER root
WORKDIR /app

RUN apk add --no-cache \
    bash \
    ca-certificates \
    libstdc++ \
    tini && \
    test -x /opt/openssl/bin/openssl && \
    test -f /opt/openssl/lib64/libssl.so && \
    test -f /opt/openssl/lib64/libcrypto.so && \
    addgroup -S -g 10001 pqctls && \
    adduser -S -D -H -u 10001 -G pqctls -s /sbin/nologin pqctls && \
    mkdir -p /app/bin /app/config /app/certs /app/logs && \
    chown -R 10001:10001 /app

COPY --from=build --chown=10001:10001 /tmp/build/tls_crypto_server /app/bin/tls_crypto_server
COPY --chown=10001:10001 container/config/*.json /app/config/
COPY --chown=10001:10001 container/entrypoint.sh /app/entrypoint.sh

RUN chmod 0555 /app/bin/tls_crypto_server /app/entrypoint.sh && \
    chmod 0750 /app/logs

ENV LD_LIBRARY_PATH="/opt/openssl/lib64:/opt/openssl/lib"
ENV OPENSSL_BIN="/opt/openssl/bin/openssl"
ENV OPENSSL_MODULES="/opt/openssl/lib64/ossl-modules"

USER 10001:10001

EXPOSE 8443 8444 8445
STOPSIGNAL SIGTERM

ENTRYPOINT ["/sbin/tini", "--", "/app/entrypoint.sh"]
