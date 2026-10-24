# Apple APNs Courier

A small, auditable Python implementation of the Apple Push Notification
service (APNs) device-side Courier protocol.

The package can:

- authenticate to `courier.push.apple.com` with an activation certificate and
  its matching RSA private key;
- mint a fresh base token;
- request a topic-scoped token;
- subscribe to a topic;
- receive and acknowledge notification frames;
- verify Courier TLS with normal certificate and hostname validation.

It is a protocol client, not an APNs provider. A provider or an existing push
service must register the topic-scoped device token and send notifications to
it.

## Security notice

This project contains no real certificates, private keys, device tokens, push
credentials, or account data.

An APNs activation identity is sensitive and device-specific. Only use
material from a device you own or are explicitly authorized to test. Keep the
private key and generated token files outside Git. The supplied `.gitignore`
excludes common local state paths, but you remain responsible for checking
files before publishing.

## Device material

For the implemented device-side flow, two matching objects are required:

1. the activation X.509 certificate (`identity.der` or PEM), which is public;
2. the matching activation RSA private key (`activation-private.der` or PEM),
   which is secret.

The private key must be exportable. The validated iPhone 6s test identity used
RSA 1024 with `kSecAttrIsExtractable=1`.

Do not extract or commit unrelated keys such as UIK/SIK material. Base tokens
and scoped tokens are generated at runtime and do not need to be supplied by
the device. They become local secrets after this client receives them.

## Install

Python 3.10 or newer is required.

```bash
python -m pip install .
```

For development:

```bash
python -m pip install -e ".[dev]"
pytest
```

## 1. Request a scoped token

```bash
apple-apns-courier token \
  --certificate /secure/path/identity.der \
  --private-key /secure/path/activation-private.der \
  --topic com.example.application \
  --token-dir ./apns-state
```

This creates:

```text
apns-state/
  base-token.bin
  scoped-token.bin
  metadata.json
```

The binary token files are local secrets. `metadata.json` contains only the
topic, file sizes, and SHA-256 digests.

Register the scoped token with the service that will send notifications. The
wire token is binary; many services expect lowercase hexadecimal:

```bash
python -c "from pathlib import Path; print(Path('apns-state/scoped-token.bin').read_bytes().hex())"
```

## 2. Listen and acknowledge one notification

```bash
apple-apns-courier listen \
  --certificate /secure/path/identity.der \
  --private-key /secure/path/activation-private.der \
  --topic com.example.application \
  --token-dir ./apns-state \
  --timeout 120
```

Start `listen` before asking the external provider to send. The command
authenticates with the saved base token, subscribes to the topic, waits for a
matching notification, acknowledges it, and exits.

Use `--save-notification notification.json` to retain the payload.

## Library use

```python
from apple_apns_courier import ActivationIdentity, CourierClient

identity = ActivationIdentity.from_files(
    certificate_path="identity.der",
    private_key_path="activation-private.der",
)

with CourierClient.connect(identity) as client:
    base = client.base_token
    scoped = client.request_scoped_token("com.example.application")
    client.subscribe("com.example.application")
    notification = client.wait_for_notification(
        "com.example.application",
        timeout=120,
    )
    print(notification.message_id.hex())
```

## TLS

TLS verification is mandatory. The default trust store is the Python/OpenSSL
system trust store. If your platform does not trust the Apple server chain,
provide an Apple root CA explicitly:

```bash
apple-apns-courier token ... --ca-file AppleRootCA.pem
```

The client requests ALPN `apns-security-v3` but accepts a server that does not
select an ALPN protocol, matching the observed production behavior.

## Scope and limitations

- The tested environment was a physical iPhone activation identity with
  Windows running all network operations.
- The project does not implement an APNs provider API.
- It does not bypass APNs topic registration, service-side token registration,
  app entitlements, or notification-display policy.
- A non-exportable SEP-backed signing key cannot be used by this library
  without a device-assisted signing transport.
- APNs tokens and activation identities may rotate. Re-extract matching
  material if authentication stops working.
- Long-running reconnects, token persistence across identity rotation, and
  multiple concurrent topics are not yet part of the validated public API.

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the observed Courier frame layout.

## License

This project is licensed under the GNU General Public License, version 3 only
(`GPL-3.0-only`). See [LICENSE](LICENSE).
