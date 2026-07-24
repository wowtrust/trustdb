# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG BASE_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG VALIDATOR_BUILDER_IMAGE=docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651

FROM ${BASE_IMAGE} AS source
ADD --checksum=sha256:9a8d1e83ec7664f799255b0dec5baebde2d12b6578b29cfadf92316b3d3e221c \
    https://github.com/alibaba/tengine/archive/refs/tags/2.3.4.tar.gz /tmp/tengine.tar.gz
ADD --checksum=sha256:57c2741750a699bfbdaa1bbe44a5733e9c8fc65d086c210151cfbc2bbd6fc975 \
    https://github.com/Tongsuo-Project/Tongsuo/archive/refs/tags/8.4.0.tar.gz /tmp/tongsuo.tar.gz
RUN mkdir -p /src/tengine /src/tongsuo \
    && tar -xzf /tmp/tengine.tar.gz --strip-components=1 -C /src/tengine \
    && tar -xzf /tmp/tongsuo.tar.gz --strip-components=1 -C /src/tongsuo \
    && test "$(sha256sum /src/tengine/LICENSE | cut -d ' ' -f 1)" = "8444037a744ac508f6c76aa334d73a2f9ca0bf53317d078ddf43626ccfa10deb" \
    && test "$(sha256sum /src/tongsuo/LICENSE.txt | cut -d ' ' -f 1)" = "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"

FROM ${BASE_IMAGE} AS builder
ARG SOURCE_DATE_EPOCH=1702545703
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} \
    TZ=UTC \
    LC_ALL=C
COPY --from=source /src /src
RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260713T000000Z bookworm main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260713T000000Z bookworm-updates main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20260713T000000Z bookworm-security main' \
      > /etc/apt/sources.list \
    && : > /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
      build-essential=12.9 \
      libpcre3-dev=2:8.39-15 \
      perl=5.36.0-7+deb12u3 \
      zlib1g-dev=1:1.2.13.dfsg-1 \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src/tengine
RUN ./configure \
      --add-module=modules/ngx_openssl_ntls \
      --build=trustdb-tlcp-gateway-reproducible \
      --conf-path=/etc/trustdb/tlcp/nginx.conf \
      --error-log-path=stderr \
      --group=trustdb \
      --http-log-path=/dev/stdout \
      --http-proxy-temp-path=/var/cache/tlcp-gateway/proxy \
      --lock-path=/run/tlcp-gateway/tlcp-gateway.lock \
      --pid-path=/run/tlcp-gateway/tlcp-gateway.pid \
      --prefix=/opt/tlcp-gateway \
      --sbin-path=/usr/local/sbin/tlcp-gateway \
      --user=trustdb \
      '--with-cc-opt=-O2 -fdebug-prefix-map=/src=. -ffile-prefix-map=/src=. -fno-record-gcc-switches -Wno-deprecated-declarations' \
      --with-http_ssl_module \
      --with-http_v2_module \
      '--with-ld-opt=-Wl,--build-id=none' \
      --with-openssl=/src/tongsuo \
      '--with-openssl-opt=enable-ntls no-tests' \
      --with-stream \
      --with-stream_ssl_module \
      --with-stream_ssl_preread_module \
    && make -j2 \
    && make install \
    && install -D -m 0755 /src/tongsuo/.openssl/bin/openssl /opt/tongsuo/bin/openssl \
    && install -D -m 0644 /src/tengine/LICENSE /licenses/Tengine-LICENSE \
    && install -D -m 0644 /src/tongsuo/LICENSE.txt /licenses/Tongsuo-LICENSE.txt \
    && /usr/local/sbin/tlcp-gateway -V 2>&1 | grep -F 'Tengine/2.3.4' \
    && /opt/tongsuo/bin/openssl version | grep -F 'Tongsuo 8.4.0'

FROM ${VALIDATOR_BUILDER_IMAGE} AS profile-validator
ARG SOURCE_DATE_EPOCH=1702545703
ENV CGO_ENABLED=0 \
    GOFLAGS=-mod=readonly \
    GOTOOLCHAIN=local \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /src/trustdb
COPY packaging/tlcp-gateway/validator-go.mod ./go.mod
COPY packaging/tlcp-gateway/validator-go.sum ./go.sum
RUN set -eu; \
    for module in \
      github.com/emmansun/gmsm@v0.44.0 \
      github.com/fxamacker/cbor/v2@v2.9.1 \
      github.com/x448/float16@v0.8.4 \
      golang.org/x/crypto@v0.53.0 \
      golang.org/x/net@v0.56.0 \
      golang.org/x/text@v0.38.0; do \
      attempt=1; \
      until go mod download "$module"; do \
        [ "$attempt" -lt 5 ] || exit 1; \
        sleep "$attempt"; \
        attempt=$((attempt + 1)); \
      done; \
    done; \
    go mod verify
COPY internal/cborx ./internal/cborx
COPY internal/cryptosuite ./internal/cryptosuite
COPY internal/tlcpprofile ./internal/tlcpprofile
COPY internal/tlcpready ./internal/tlcpready
COPY cmd/trustdb-tlcp-profile ./cmd/trustdb-tlcp-profile
COPY cmd/trustdb-tlcp-readiness ./cmd/trustdb-tlcp-readiness
RUN go build -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' \
      -o /out/trustdb-tlcp-profile \
      ./cmd/trustdb-tlcp-profile \
    && go build -trimpath -buildvcs=false \
      -ldflags='-s -w -buildid=' \
      -o /out/trustdb-tlcp-readiness \
      ./cmd/trustdb-tlcp-readiness

FROM ${BASE_IMAGE} AS gateway
ARG SOURCE_DATE_EPOCH=1702545703
LABEL org.opencontainers.image.title="TrustDB TLCP gateway" \
      org.opencontainers.image.description="Pinned Tengine and Tongsuo TLCP mutual-authentication gateway" \
      org.opencontainers.image.source="https://github.com/wowtrust/trustdb" \
      org.opencontainers.image.version="tengine-2.3.4_tongsuo-8.4.0" \
      org.opencontainers.image.created="2023-12-14T09:21:43Z" \
      org.opencontainers.image.licenses="BSD-2-Clause AND Apache-2.0" \
      org.opencontainers.image.tengine.commit="698e1798e8d691c55b5405ca1526c3dca4759d47" \
      org.opencontainers.image.tongsuo.commit="a8ae0925d26de3b449f7a21767910cd41291bcd8"
RUN printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20260713T000000Z bookworm main' \
      > /etc/apt/sources.list \
    && : > /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends libpcre3=2:8.39-15 \
    && rm -rf /var/lib/apt/lists/* /var/log/apt/* \
    && rm -f /var/cache/ldconfig/aux-cache /var/log/dpkg.log
COPY --from=builder /usr/local/sbin/tlcp-gateway /usr/local/sbin/tlcp-gateway
COPY --from=builder /opt/tongsuo/bin/openssl /opt/tongsuo/bin/openssl
COPY --from=profile-validator /out/trustdb-tlcp-profile /usr/local/bin/trustdb-tlcp-profile
COPY --from=profile-validator /out/trustdb-tlcp-readiness /usr/local/bin/trustdb-tlcp-readiness
COPY --from=builder /etc/trustdb/tlcp/mime.types /opt/tlcp-gateway/conf/mime.types
COPY --from=builder /licenses /usr/share/licenses/trustdb-tlcp-gateway
COPY packaging/tlcp-gateway/baseline.json /usr/share/trustdb/tlcp-gateway/build-baseline.json
COPY packaging/tlcp-gateway/entrypoint.sh /usr/local/bin/tlcp-gateway-entrypoint
COPY packaging/tlcp-gateway/prepare-runtime.sh /usr/local/bin/tlcp-gateway-prepare-runtime
RUN mkdir -p /etc/trustdb/tlcp /var/cache/tlcp-gateway/proxy /run/tlcp-gateway \
    && printf '%s\n' 'trustdb:x:10001:' >> /etc/group \
    && printf '%s\n' 'trustdb:x:10001:10001:TrustDB TLCP gateway:/nonexistent:/usr/sbin/nologin' >> /etc/passwd \
    && chown -R 10001:10001 /var/cache/tlcp-gateway /run/tlcp-gateway \
    && chmod 0755 \
      /usr/local/bin/tlcp-gateway-entrypoint \
      /usr/local/bin/tlcp-gateway-prepare-runtime \
    && test "$(sha256sum /usr/share/licenses/trustdb-tlcp-gateway/Tengine-LICENSE | cut -d ' ' -f 1)" = "8444037a744ac508f6c76aa334d73a2f9ca0bf53317d078ddf43626ccfa10deb" \
    && test "$(sha256sum /usr/share/licenses/trustdb-tlcp-gateway/Tongsuo-LICENSE.txt | cut -d ' ' -f 1)" = "7d5450cb2d142651b8afa315b5f238efc805dad827d91ba367d8516bc9d49e7a"
USER 10001:10001
WORKDIR /run/tlcp-gateway
ENV PATH=/opt/tongsuo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EXPOSE 8443 9443
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=10s --start-period=5s --retries=2 \
  CMD ["/usr/local/bin/trustdb-tlcp-readiness"]
ENTRYPOINT ["/usr/local/bin/tlcp-gateway-entrypoint"]
