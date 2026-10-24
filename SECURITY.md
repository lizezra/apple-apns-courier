# Security Policy

## Reporting a vulnerability

Open a private security advisory on GitHub rather than a public issue.

Include the affected version, a minimal reproducer, and whether the issue can
expose private keys, device tokens, or notification contents.

Do not include real activation private keys or live APNs tokens in reports.

## Sensitive files

The following are secret local state:

- activation private keys;
- `base-token.bin`;
- `scoped-token.bin`;
- provider registration keys derived from a scoped token;
- received notification payloads that may contain user data.

Certificates are public but still device-specific. Publishing a certificate
links research activity to a device identity and should usually be avoided.
