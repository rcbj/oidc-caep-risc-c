# `docker build --target test` runs the suite in this image.
# The demo image below does not run it.
FROM debian:bookworm AS test
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/build && ctest --test-dir /tmp/build --output-on-failure

FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential cmake pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B /tmp/build -DCMAKE_BUILD_TYPE=Release && cmake --build /tmp/build --target oidc-caep-risc-demo

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 openssl curl ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /tmp/build/oidc-caep-risc-demo /app/oidc-caep-risc-demo
COPY demo demo
COPY scripts scripts
COPY LICENSE README.md VERSION ./
COPY demo/entrypoint.sh /entrypoint.sh
RUN chmod 755 /entrypoint.sh
ENV PORT=3000
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD curl -fsS "http://127.0.0.1:$$PORT/healthz" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/app/oidc-caep-risc-demo"]
