# TrustDB release package

This archive contains the TrustDB server and CLI in one executable, the production configuration template, and the compiled Admin Web assets.

Run `trustdb version` to inspect the exact version, commit, target operating system, and architecture. Generate keys before starting a server:

Before extracting this archive, verify the signed
`TRUSTDB_RELEASE_MANIFEST.json` with the independently provisioned Sigstore
trusted root, then run `trustdb release verify --dir <release-directory>` with
a previously admitted verifier. The release directory must contain the exact
manifested file set plus the attestation bundle; SHA-256 and SM3 must both
match. See the [air-gap release
runbook](https://github.com/wowtrust/trustdb/blob/main/docs/compliance/SUPPLY_CHAIN_RELEASES.md).

```bash
mkdir -p ./trustdb-data/keys
read -r -s -p 'Development key passphrase: ' TRUSTDB_DEV_KEY_PASSPHRASE
export TRUSTDB_DEV_KEY_PASSPHRASE
printf '\n'
trustdb keygen --out ./trustdb-data/keys --prefix server
trustdb keygen --out ./trustdb-data/keys --prefix client
unset TRUSTDB_DEV_KEY_PASSPHRASE
```

The built-in passphrase provider is a development/offline facility. It accepts
exactly one of `TRUSTDB_DEV_KEY_PASSPHRASE` or
`TRUSTDB_DEV_KEY_PASSPHRASE_FILE`; the latter must name an owner-only regular
file supplied by a service secret manager. Never put the passphrase in argv or
logs, and keep a secret file outside the key/envelope directory and its backup
volume. Windows software-envelope persistence currently fails closed until an
owner-only DACL is continuously runtime-qualified; use an approved external
signer there, or explicit `--protection plaintext-dev-v1` only for disposable
evaluation.

Copy `config/production.yaml`, adjust paths and deployment settings, and set `keys.server_private` plus either `keys.client_public` or a key registry. To enable the bundled Admin Web, configure `admin.enabled`, credentials, a session secret of at least 32 bytes, and set `admin.web_dir` to this package's `admin` directory.

TiKV remains compiled into every server/CLI package. Set `metastore: tikv` and provide `proofstore.tikv_pd_endpoints`, `proofstore.tikv_keyspace`, and `proofstore.tikv_namespace` when deploying against a TiKV cluster.

Linux packages also contain `bin/trustdb-signer-pkcs11`, the isolated native
PKCS#11 signer sidecar. It loads no module until explicitly configured and
does not change the default software-signer path. Follow
[`docs/integrations/PKCS11_SIGNER.md`](https://github.com/wowtrust/trustdb/blob/main/docs/integrations/PKCS11_SIGNER.md)
for token preparation, owner-only PIN files, mechanism profiles, and hardware
qualification. macOS and Windows packages do not currently bundle this
optional native sidecar.

Linux packages also contain `bin/trustdb-signer-sdf`. It loads only TrustDB's
versioned adapter ABI; it does not bundle, link, or qualify a proprietary SDF
library. Build the deployment-specific adapter shim against the purchased
device SDK, mount owner-only adapter configuration and credential files, and
follow
[`docs/integrations/SDF_SIGNER.md`](https://github.com/wowtrust/trustdb/blob/main/docs/integrations/SDF_SIGNER.md).
The ordinary TrustDB server remains usable without SDF, and no adapter is
loaded until the `sdf` signer plugin is explicitly configured.
