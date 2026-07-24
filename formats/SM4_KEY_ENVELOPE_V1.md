# TrustDB SM4 Software-Key Envelope V1

Status: available for software-managed signer descriptors whose
`software.protection` is `sm4-envelope-v1`.

## Boundary

This format protects private-key bytes at rest. It does not change a key's
public bytes, KeyID, signature algorithm, TrustDB proof inputs, registry
history, or verification semantics. The built-in passphrase KEK provider is a
development/offline facility. Software encryption is not an HSM, SDF, KMS, or
certified commercial-cryptography custody boundary.

Logical TrustDB backups contain proofstore evidence and restore state only.
They do not include signer descriptors, envelope files, passphrases, KEKs, or
provider credentials. Operators must back up production keys through their
approved HSM/KMS/provider ceremony; copying a software envelope and its
passphrase together defeats the separation intended by envelope encryption.

## Canonical outer format

The file is RFC 8949 deterministic CBOR with schema
`trustdb.software-key-envelope.v1`. Decoders reject unknown fields, duplicate
map keys, tags, indefinite-length values, non-canonical encodings, trailing
bytes, unsupported versions/algorithms, and files larger than 16 KiB. Parsing
is provider-neutral: opening, not generic decoding, rejects a provider that is
not registered by the caller.

```text
schema_version     trustdb.software-key-envelope.v1
object_type        software-private-key
metadata           crypto_suite, key_id, key_algorithm,
                   private_key_encoding
content_algorithm  SM4-GCM
content_nonce      12 bytes
ciphertext         private-key ciphertext || 16-byte tag
wrapped_dek        provider, algorithm, canonical provider parameters,
                   wrapped DEK ciphertext
```

The trusted key descriptor supplies the expected metadata. Opening compares
all four fields before asking a KEK provider to unwrap anything. Envelope-owned
metadata is never allowed to lower the caller's expected suite, KeyID,
algorithm, encoding, protection, or provider policy.

## Content encryption and AAD

Every new envelope generates a fresh random 128-bit DEK and 96-bit content
nonce. The private key is sealed with SM4-GCM and a fixed 128-bit tag. ECB,
CBC, CTR, truncated tags, and configurable nonce/tag sizes are unsupported.

Content AAD is deterministic CBOR containing:

```text
domain               trustdb.software-key-envelope.v1
object_type           software-private-key
crypto_suite          descriptor crypto_suite
key_id                descriptor key_id
key_algorithm         descriptor algorithm
private_key_encoding  descriptor software.encoding
content_algorithm     SM4-GCM
```

Changing any descriptor-bound field, nonce, ciphertext, or tag causes opening
to fail before a signer is returned.

## KEK provider contract

`KEKProvider` exposes only provider name plus wrap/unwrap operations for the
random DEK. Core code does not require raw KEK export. HSM/KMS adapters may
therefore return an opaque wrapped DEK and canonical provider parameters while
performing the privileged operation inside their own boundary.

The provider wrap authenticates the content AAD, provider name, wrap algorithm,
and exact provider-parameter bytes. Rotation first authenticates both the old
wrapped DEK and content ciphertext, then creates a fresh wrap and atomically
replaces the file. The private key ciphertext, public key, KeyID, and historical
verification references stay unchanged. Reusing the previous provider
parameters in one rotation is rejected.

## Development passphrase provider

The built-in `passphrase-dev-v1` provider reads the passphrase from
exactly one of `TRUSTDB_DEV_KEY_PASSPHRASE` or the owner-only regular file named
by `TRUSTDB_DEV_KEY_PASSPHRASE_FILE`; TrustDB never accepts the secret as an
ordinary CLI flag. For rotation, the replacement source is exactly one of the
corresponding `_NEW` variables. Secret files must remain outside the envelope
directory and its backup volume. The provider's canonical parameters are:

```text
kdf         PBKDF2-HMAC-SM3
salt        16 fresh random bytes
iterations  default 200000; accepted range 100000..2000000
kek_bytes   16
nonce       12 fresh random bytes
tag_bytes   16
```

The random salt derives a new SM4 KEK for each wrap, and each wrap also uses a
fresh nonce. KDF work factors outside the fixed range fail before expensive
derivation, preventing both downgrade and parser-controlled denial of service.
Passphrases must be 12..1024 bytes. Derived KEKs, DEKs, passphrase byte copies,
opened private material, and temporary envelope buffers are cleared on a
best-effort basis; Go and operating-system copies cannot be guaranteed erased.

## Persistence and failure behavior

On supported Unix systems, envelope creation holds an owner-only adjacent lock
while using an owner-only same-directory temporary file, file `fsync`,
no-replace installation, and directory `fsync`. KEK rotation holds that same
OS lock across the complete read/authenticate/rewrap/atomic-replace transaction,
so a concurrent or stale process must authenticate the winning envelope before
it can publish. Process exit releases the kernel lock. Symlinks, non-regular
files, unsafe permissions, missing rotation targets, callback/serialization
failure, and unsupported directory durability fail closed without changing the
previous envelope. Rotation creates no plaintext or `.bak` copy.

Windows software-envelope persistence intentionally returns unsupported until
TrustDB can continuously runtime-qualify owner-only DACL creation and checking
across its supported Windows environments. Callers must use an approved
external signer or, for disposable development only, explicitly select
`plaintext-dev-v1`; there is no silent downgrade.

Wrong passphrases, wrong KEKs, modified tags, KDF/provider-parameter changes,
truncation, schema/algorithm downgrades, descriptor mismatch, and unregistered
providers all fail before key use. Authentication diagnostics do not contain
passphrases, key bytes, material paths, or provider credentials.
