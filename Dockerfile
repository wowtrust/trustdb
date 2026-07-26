ARG NODE_IMAGE=docker.io/library/node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d
ARG GO_IMAGE=docker.io/library/golang:1.26.5-bookworm@sha256:1ecb7edf62a0408027bd5729dfd6b1b8766e578e8df93995b225dfd0944eb651
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS admin-web
WORKDIR /src/clients/web
COPY clients/web/package.json clients/web/package-lock.json ./
RUN npm ci
COPY clients/web/ ./
RUN npm run build

FROM ${GO_IMAGE} AS server
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG VCS_REF=none
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
COPY third_party/fisco-bcos/ ./third_party/fisco-bcos/
RUN go mod download
COPY . ./
ENV CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION -X main.commit=$VCS_REF -X main.date=$BUILD_DATE" \
    -o /out/trustdb ./cmd/trustdb

FROM ${RUNTIME_IMAGE}
ARG VERSION=dev
ARG VCS_REF=none
ARG BUILD_DATE=unknown
ARG DEBIAN_SNAPSHOT=20260713T000000Z
LABEL org.opencontainers.image.title="TrustDB" \
      org.opencontainers.image.description="Verifiable evidence database server and CLI" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.source="https://github.com/wowtrust/trustdb" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN sed -i \
      -e "s|http://deb.debian.org/debian-security|http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|g" \
      -e "s|http://deb.debian.org/debian|http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|g" \
      /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
      ca-certificates=20230311+deb12u1 \
      curl=7.88.1-10+deb12u15 \
      tini=0.19.0-1+b3 \
      tzdata=2026b-0+deb12u1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 trustdb \
    && useradd --uid 10001 --gid trustdb --home-dir /var/lib/trustdb --create-home trustdb \
    && install -d -o trustdb -g trustdb /etc/trustdb /opt/trustdb/admin /var/lib/trustdb

COPY --from=server /out/trustdb /usr/local/bin/trustdb
COPY --from=admin-web /src/clients/web/dist/ /opt/trustdb/admin/
COPY configs/docker.yaml /etc/trustdb/config.yaml
COPY packaging/docker/entrypoint.sh /usr/local/bin/trustdb-entrypoint

RUN chmod 0755 /usr/local/bin/trustdb /usr/local/bin/trustdb-entrypoint \
    && chown -R trustdb:trustdb /etc/trustdb /opt/trustdb /var/lib/trustdb

USER trustdb
WORKDIR /var/lib/trustdb
ENV TRUSTDB_CONFIG=/etc/trustdb/config.yaml \
    TRUSTDB_ADMIN_WEB_DIR=/opt/trustdb/admin \
    TRUSTDB_HEALTH_SERVER_NAME=trustdb
VOLUME ["/var/lib/trustdb"]
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl --fail --silent --cacert /etc/trustdb/tls/server-ca.crt \
    --cert /etc/trustdb/tls/health-client.crt --key /etc/trustdb/tls/health-client.key \
    --resolve "${TRUSTDB_HEALTH_SERVER_NAME}:8080:127.0.0.1" \
    "https://${TRUSTDB_HEALTH_SERVER_NAME}:8080/healthz" >/dev/null || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/trustdb-entrypoint"]
CMD ["serve"]
