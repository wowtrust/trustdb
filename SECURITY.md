# Security Policy

TrustDB handles signatures, proof material, durable records, and recovery state. Please do not disclose a suspected vulnerability in a public issue, discussion, pull request, or chat.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

https://github.com/wowtrust/trustdb/security/advisories/new

Include, when available:

- the affected version or commit;
- the affected component and deployment configuration;
- reproduction steps or a minimal proof of concept;
- the expected and observed security boundary;
- whether keys, proof verification, WAL durability, restore, authorization, or remote code execution are involved.

Do not include real customer data, production credentials, private keys, or access tokens. Use newly generated test identities and disposable data.

We will acknowledge a complete report as soon as practical, coordinate validation and remediation with the reporter, and publish an advisory when users have an actionable fix or mitigation. Timelines depend on severity, reproducibility, and release complexity.

## Supported versions

Security fixes are made against the latest stable release and the current `main` branch. Older releases may require upgrading before a fix can be applied.

## Scope notes

TrustDB verifies cryptographic evidence, but it does not by itself establish the real-world identity behind a key. Production deployments must protect private keys, trusted public-key configuration, network ingress, administrator access, backups, and the host operating system.

The HTTP and gRPC business APIs do not replace TLS, client authentication, tenant authorization, or network policy. See the deployment documentation before exposing a service outside a controlled network.
