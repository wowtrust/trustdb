# TrustDB Roadmap

This roadmap communicates product direction without promising dates. Implemented behavior is documented in the README, website, stable formats, and releases. Proposed work remains subject to design review, security boundaries, compatibility, and maintainer capacity.

## Now: make adoption simple

- Keep the file-to-`.sproof` onboarding path reproducible on Linux, macOS, and Windows.
- Improve deployment safety guidance, release verification, and operational diagnostics.
- Publish small integration examples for audit events, release artifacts, SBOMs, and data handoffs.
- Grow externally approachable issues, discussions, and contributor documentation.
- Maintain proof-format interoperability vectors and offline-verification coverage.

## Next: production integration

- Add client libraries or reference clients for commonly requested non-Go environments.
- Provide deployment examples for reverse proxies, TLS/mTLS, metrics, and container orchestration.
- Expand key custody and signing-provider options without weakening verifier trust boundaries.
- Improve ecosystem integrations for object storage, source-code forges, software supply-chain evidence, and external anchors.
- Validate TiKV-backed deployments and publish reproducible operating profiles.

## Later: cryptographic and ecosystem expansion

- Evaluate versioned cryptographic-agility profiles and national-cryptography interoperability.
- Evaluate additional independently verifiable anchoring systems.
- Improve multi-party data-handoff conventions built on stable proof containers.
- Publish production adoption and interoperability reports when real deployments permit it.

## How to influence the roadmap

Start with a [GitHub Discussion](https://github.com/wowtrust/trustdb/discussions) describing the user, workflow, deployment constraints, evidence boundary, and expected verification experience. A feature becomes implementation work only after a scoped issue is accepted.

The detailed engineering backlog is maintained separately from this public product roadmap. Open issues labeled [`help wanted`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22) or [`good first issue`](https://github.com/wowtrust/trustdb/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are the best entry points for external contributors.
