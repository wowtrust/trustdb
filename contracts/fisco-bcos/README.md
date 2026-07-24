# TrustDBAnchorV1

`TrustDBAnchorV1.sol` is the immutable FISCO BCOS publication boundary for the
chain-neutral `AnchorPayload v1` defined by
[ADR-0013](../../docs/integrations/ADR-0013-FISCO-BCOS-ANCHOR-PROTOCOL.md).
It stores no business payload, personal information, TrustDB proof, private key,
or mutable implementation address.

## Contract semantics

`publish` accepts the canonical AnchorID and the payload fields needed to bind
the event offline:

- StreamID
- tree size
- TrustDB root bytes
- canonical Signed STH digest
- payload version

The publication additionally binds the authorized caller (`msg.sender`) as the
publisher recorded in storage and emitted in the event; publisher is not a
caller-supplied calldata field.

An exact duplicate returns `false` without emitting a second event. It remains
successful after newer tree sizes have been published, which makes retry after
an unknown transaction outcome safe. Duplicate equality covers the immutable
payload fields, not the submitting authorized account, so a replacement
publisher can safely retry; the stored record preserves the publisher that
created it. Reusing an AnchorID with changed fields, regressing a stream tree
size, or publishing a different root at the current tree size reverts. A
successful new record returns `true` and emits exactly one `AnchorPublished`
event.

The contract does not recalculate AnchorID. Standard and Guomi BCOS use
different native hashing rules while the TrustDB payload remains
chain-neutral. The sink and offline verifier must recompute AnchorID from the
canonical payload and compare every event field.

## Authorization and lifecycle

The constructor fixes one immutable administrator and at least one initial
publisher. The administrator can authorize or revoke publishers; every role
change is emitted, and revoking the last publisher is rejected so an accidental
role update cannot freeze publication. There is no proxy, implementation slot,
delegate call, self-destruct path, or administrator replacement. Losing the
administrator key requires deploying and locally pinning a new contract.

Production deployments should use a dedicated administrator kept offline and a
separate HSM/KMS-backed publisher. The deployment record must list both roles
and must never contain key material.

The machine-readable role contract is recorded in `roles.v1.json`.

## Reproducible build

Builds use the two FISCO BCOS Solidity 0.8.11 compilers pinned by ADR-0012:

```bash
python3 scripts/fisco-bcos/build_anchor_contract.py \
  --platform linux/amd64 \
  --cache-dir /tmp/trustdb-fisco-cache \
  --check
```

The command verifies upstream compiler archives before use, compiles standard
and Guomi artifacts with identical settings, and compares them with
`artifacts/manifest.json`. Use `--write` only when intentionally creating a new
contract version.

Artifact hashes are audit identities, not trust roots. A verifier must pin the
deployed chain, group, contract address, runtime code hash, protocol version,
and validator checkpoint in its local `TrustConfig`.

## Guomi deployment and startup

Guomi mode is a complete chain-mode binding, not a different encoding of a
standard-chain transaction. Deploy the contract from `artifacts/guomi`, then
create a canonical `trustdb.fisco-bcos-trust-config.v1` CBOR file with:

- `crypto_mode=guomi`, protocol and chain hashes set to SM3, account and
  validator signatures set to SM2-with-SM3, and the fixed TrustDB SM2 user ID;
- `gm-tls://host:port` endpoints, the exact chain/group/genesis/checkpoint, the
  deployed address, and the SM3 runtime-code hash;
- every validator's 65-byte uncompressed SM2 public key and a `node_id` equal
  to `0x` plus that public key's 64-byte body;
- the SM3 digest of the exact trusted CA file and separate `sm_sdk` signing and
  `sm_ensdk` encryption certificate/key references; and
- an account provider exposing the `FISCO_BCOS_GUOMI_V1` signer profile. For
  PKCS#11 or SDF providers, the private key remains inside the provider.

Start the native-enabled server with:

```bash
trustdb serve \
  --anchor-sink=fisco-bcos \
  --anchor-fisco-bcos-trust-config=/absolute/path/trust-config.cbor
```

The binary must be built with `CGO_ENABLED=1`, the `fiscobcos_sdk` build tag,
and the pinned FISCO BCOS C SDK available to the dynamic loader. Before
connecting, TrustDB verifies the Guomi CA, certificate chains, signing and
encryption key usages, private-key matches, and distinct dual-certificate
identities. It also rejects standard TLS endpoints, secp256k1 validators,
standard contract artifacts, and standard-chain transaction material under a
Guomi configuration.

Offline verification uses the verifier's local `TrustConfig` as the trust
root. It recomputes SM3 transaction, receipt, event, block, and contract
bindings and verifies the pinned SM2 PBFT validator quorum without contacting
the chain. The anchored TrustDB payload and its evidence cryptographic suite
remain unchanged and opaque to FISCO BCOS.

## Deployment record

Copy `deployments/deployment-record.template.json` into a controlled deployment
evidence repository, fill it from finalized chain data, and sign the record
according to the operator's change-control process. Do not commit production
addresses, account identifiers, or certificate material to this repository.
