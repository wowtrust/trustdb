# TrustDB SDF recovery bundle v1

Status: available as the provider recovery artifact for the optional SDF
integration.

`trustdb.sdf-recovery-bundle.v1` preserves the stable references needed to
rebind an SDF deployment after a sidecar restart or provider-state recovery.
It does not contain credentials, adapter configuration, private SM2 keys,
plaintext SM4 keys, or native session handles.

This object is not a `.tdbackup` archive. Encrypted `.tdbackup v5` preserves
proofstore evidence, the public key-registry audit log, and anchor provider
state, but the SDF recovery bundle remains a separately governed provider
artifact. It must be protected and restored through the SDF custody ceremony.

## Encoding and bounds

- The object is RFC 8949 Core Deterministic CBOR.
- `schema_version` is exactly `trustdb.sdf-recovery-bundle.v1`.
- The encoded object is at most 16 MiB.
- `signer_descriptors` contains 1–128 entries.
- `wrapped_sm4_keys` contains 0–1024 entries.
- Decode-time array and map limits are enforced before collection allocation.
- Unknown or duplicate map keys, tags, indefinite-length values, NaN, Inf,
  excessive nesting, trailing bytes, non-canonical integers/lengths, and
  non-canonical complete objects are rejected.

## Fields

```text
schema_version       fixed text string
device               complete DeviceIdentity
signer_descriptors   array of canonical trustdb.key-descriptor.v1 byte strings
wrapped_sm4_keys     array of canonical trustdb.sdf-wrapped-sm4-key.v1 byte strings
checksum_sm3         32-byte SM3 over the canonical payload below
```

`DeviceIdentity` contains the bounded `adapter_id`, `adapter_version`,
`device_id`, `serial`, and `firmware` strings returned by the adapter. Empty,
control-character, over-limit, or changed values fail closed.

Each embedded signer descriptor must:

- be a canonical `trustdb.key-descriptor.v1` signer;
- select `provider=sdf` and `CN_SM_V1`/SM2-SM3;
- contain the fixed SM2 user ID and canonical 65-byte public key;
- bind the bundle device ID, a non-zero internal key index, and a credential
  reference; and
- have a unique KeyID and unique
  `{device_ref, key_index, credential_ref}` provider handle within the bundle.

Each wrapped-key entry binds the complete same device identity plus the stable
KEK ID/index. It contains only the device-produced wrapped blob, never a
plaintext key or serializable session handle.

The two arrays are sorted by ascending bytewise order of their complete
canonical embedded objects. Duplicate or out-of-order entries are invalid.

## Checksum

`checksum_sm3` is:

```text
SM3(CoreDetCBOR({
  schema_version,
  device,
  signer_descriptors,
  wrapped_sm4_keys
}))
```

This unkeyed checksum detects accidental corruption only. It is not an
authenticity control because an attacker can modify the payload and recompute
it. Off-host storage and backup v5 must authenticate and encrypt the complete
artifact.

## Export and restore contract

Export validates every input object, reads every indexed public key from the
live device, and requires an exact match with the corresponding descriptor
before encoding the bundle.

Restore performs all structural and checksum validation before native
operations. It then requires an exact match for:

- complete adapter/device identity;
- configured device and credential references;
- every indexed public key;
- requested capability set; and
- every optional wrapped key's KEK ID/index.

Wrapped keys are imported and destroyed once to prove the live KEK binding.
All recovered public-key pins are preflighted under one lock and published to
the process cache together. A conflict in any entry publishes none of the new
pins. The returned descriptors and wrapped keys are detached copies.

Missing devices, unsupported capabilities, public-key drift, credential/KEK
drift, corrupt wrapping, ambiguous handles, or native failures never trigger a
software, key, device, algorithm, or backup-format fallback.
