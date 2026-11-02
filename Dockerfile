# `docker build --target test .` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm AS test
# python3 and openssl run scripts/trust_chain.py in tests/trust.c.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates python3 openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /src
# Only what the build and the suite read, so a new trust chain in demo/ does not
# rebuild or retest anything.
COPY CMakeLists.txt VERSION ./
COPY cmake cmake
COPY include include
COPY src src
COPY tests tests
COPY scripts scripts
COPY demo/main.cpp demo/main.cpp
RUN cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/build && ctest --test-dir /tmp/build --output-on-failure
# The installed package, static and shared, consumed through find_package.
RUN sh tests/package/check.sh iya_oidc iya_oidc IYA_OIDC /tmp/build

FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt VERSION ./
COPY cmake cmake
COPY include include
COPY src src
COPY tests tests
COPY demo/main.cpp demo/main.cpp
RUN cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/build --target oidc-caep-risc-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /tmp/build/oidc-caep-risc-demo /app/oidc-caep-risc-demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
# demo/ comes after the build. .dockerignore admits one file of demo/generated:
# idp-ca.pem, the iya-sts listener CA trust chain scripts/configure_iya_sts.py
# writes where tlsCa names it. When it exists, this COPY puts it at
# /app/demo/generated/idp-ca.pem; when it does not (a fresh clone, CI), the
# directory carries nothing from demo/generated and the build still succeeds.
# The client secret and keys never enter the image.
COPY demo demo
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/oidc-caep-risc-demo"]
