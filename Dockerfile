FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS admin-web
WORKDIR /src/clients/web
COPY clients/web/package.json clients/web/package-lock.json ./
RUN npm ci
COPY clients/web/ ./
RUN npm run build

FROM golang:1.26.5-bookworm AS server
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG VCS_REF=none
ARG BUILD_DATE=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
ENV CGO_ENABLED=1 GOOS=$TARGETOS GOARCH=$TARGETARCH
RUN go build -trimpath \
    -ldflags="-s -w -X main.version=$VERSION -X main.commit=$VCS_REF -X main.date=$BUILD_DATE" \
    -o /out/trustdb ./cmd/trustdb

FROM debian:bookworm-slim
ARG VERSION=dev
ARG VCS_REF=none
ARG BUILD_DATE=unknown
LABEL org.opencontainers.image.title="TrustDB" \
      org.opencontainers.image.description="Verifiable evidence database server and CLI" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.source="https://github.com/wowtrust/trustdb" \
      org.opencontainers.image.licenses="AGPL-3.0-only"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl tini tzdata \
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
