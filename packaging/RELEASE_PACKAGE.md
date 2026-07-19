# TrustDB release package

This archive contains the TrustDB server and CLI in one executable, the production configuration template, and the compiled Admin Web assets.

Run `trustdb version` to inspect the exact version, commit, target operating system, and architecture. Generate keys before starting a server:

```bash
mkdir -p ./trustdb-data/keys
trustdb keygen --out ./trustdb-data/keys --prefix server
trustdb keygen --out ./trustdb-data/keys --prefix client
```

Copy `config/production.yaml`, adjust paths and deployment settings, and set `keys.server_private` plus either `keys.client_public` or a key registry. To enable the bundled Admin Web, configure `admin.enabled`, credentials, a session secret of at least 32 bytes, and set `admin.web_dir` to this package's `admin` directory.

TiKV remains compiled into every server/CLI package. Set `metastore: tikv` and provide `proofstore.tikv_pd_endpoints`, `proofstore.tikv_keyspace`, and `proofstore.tikv_namespace` when deploying against a TiKV cluster.
