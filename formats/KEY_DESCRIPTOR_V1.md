# TrustDB Key Descriptor v1

Status: implemented by [#449](https://github.com/wowtrust/trustdb/issues/449).

`trustdb.key-descriptor.v1` is the only key configuration format accepted by
the TrustDB CLI and server. A descriptor identifies a signing or verification
key without placing private key bytes in configuration, logs, evidence,
logical backups, or API responses.

## Encoding

- The file is RFC 8949 Core Deterministic CBOR.
- Unknown fields, duplicate map keys, tags, indefinite-length values, trailing
  bytes, oversized values, and non-canonical encodings are rejected.
- The maximum encoded descriptor size is 2 MiB, including certificate chains.
- `schema_version` must equal `trustdb.key-descriptor.v1` exactly.
- There is no JSON key-file variant. JSON output from `trustdb key inspect` is
  diagnostic output and is always redacted.

## Common fields

| Field | Meaning |
| --- | --- |
| `kind` | `signer` or `verifier` |
| `provider` | `software`, `public`, `pkcs11`, `sdf`, or `remote` |
| `crypto_suite` | An immutable suite ID such as `INTL_V1` or `CN_SM_V1` |
| `key_id` | Stable identity of the key; must match runtime configuration and returned signatures |
| `algorithm` | Must exactly match the selected suite |
| `sm2_user_id` | Empty outside `CN_SM_V1`; for `CN_SM_V1` it must equal the suite-defined `1234567812345678` |
| `public_key` | Suite-specific canonical public-key encoding and bytes |
| `certificate_chain` | Optional leaf-first DER chain; the leaf key must equal `public_key` |

Certificate bytes are evidence about a key, not an embedded trust root. A
verifier must obtain trusted roots and policy from local configuration.

## Provider union

Exactly one provider reference is allowed for a signer. A verifier uses
`provider=public` and has no signer reference.

### Software

```text
software.material_path  clean relative path below the descriptor directory
software.encoding       suite-defined private material encoding
software.protection     plaintext-dev-v1 or sm4-envelope-v1
```

The descriptor never contains private material. `plaintext-dev-v1` points to
a separate owner-readable raw-URL-base64 file, must be requested explicitly,
and is only a development/reference path. `sm4-envelope-v1` points to the
available authenticated format defined by
[`SM4_KEY_ENVELOPE_V1.md`](SM4_KEY_ENVELOPE_V1.md); resolvers never fall back to
plaintext after an invalid, unavailable, or wrong-key envelope.

The software resolver rejects absolute paths, traversal, symlinks,
non-regular files, group/other-readable material on Unix, invalid canonical
envelopes, padded or non-canonical plaintext base64, wrong key sizes, and
public/private key mismatch.

### PKCS#11

`pkcs11.uri` is a canonical PKCS#11 URI identifying a private object. Inline
`pin-value` is forbidden. Provider login, session handling, key-policy checks,
and mechanism validation are implemented by the isolated provider tracked in
[#452](https://github.com/wowtrust/trustdb/issues/452) and documented in
[`docs/integrations/PKCS11_SIGNER.md`](../docs/integrations/PKCS11_SIGNER.md).

### SDF

`sdf.device_ref`, non-zero `sdf.key_index`, and optional
`sdf.credential_ref` identify an SDF-managed private key without exporting it.
The SDF provider is implemented by #453.

### Remote

`remote.endpoint` must be HTTPS and must not contain URL credentials, query,
or fragment. `remote.handle` and `remote.credential_ref` are opaque provider
references. They are redacted from diagnostics. The actual remote provider is
registered explicitly; TrustDB never falls back to software signing.

## Resolution contract

Resolution follows this fail-closed sequence:

1. Decode and byte-for-byte revalidate canonical CBOR.
2. Validate suite, algorithm, key encoding, SM2 user ID, provider union, and
   certificate chain.
3. Require that the suite is available for production use.
4. Select exactly the provider named by the descriptor.
5. Require `sign` and `public_key` capabilities.
6. Compare provider name, key ID, algorithm, suite, public-key encoding, and
   public-key bytes exactly with the descriptor.

Any mismatch stops startup or the command. Provider unavailability,
unsupported protection, missing credentials, or unsupported hardware never
causes another provider or algorithm to be selected.

## Diagnostics and secret handling

The following fields are replaced with `<redacted>` in `String`, JSON, and CLI
inspection output:

- software material path;
- complete PKCS#11 URI;
- SDF device and credential references;
- remote endpoint, handle, and credential reference.

Public keys and certificate chains are not secrets, but private material is
never copied into a descriptor. Logical backups contain proofstore evidence,
not key material. Operators must back up provider configuration and key
custody through the provider's approved process.

## Migration and compatibility

This is a destructive configuration change. Previous files containing bare
base64 Ed25519 public or private bytes are not read, migrated, guessed, or
used as fallback. Regenerate development identities with `trustdb keygen` or
provision v1 descriptors that reference the intended production provider.
Unknown future schema versions fail explicitly.
