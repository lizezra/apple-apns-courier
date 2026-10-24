# Observed Courier Protocol

This document records the frame subset used by the client. It is based on
black-box protocol research against production Courier and is not an Apple
specification.

## Frame format

```text
command: u8
body_length: u32, big endian
body:
  repeated:
    field_id: u16, big endian
    field_length: u16, big endian
    field_value: bytes
```

The client bounds each complete body to 1 MiB and each field to 65,535 bytes.

## Commands used

| Type | Name | Purpose |
|---:|---|---|
| 7 | Connect | Present the activation identity and a signed nonce |
| 8 | ConnectAck | Connection status and base token |
| 9 | Filter | Subscribe Courier delivery to a topic |
| 10 | Message | Notification delivery |
| 11 | Receipt | Notification acknowledgement |
| 12 | KeepAlive | Application-level heartbeat |
| 13 | KeepAliveAck | Heartbeat response |
| 17 | ScopedTokenRequest | Request a token for one topic |
| 18 | ScopedTokenResponse | Topic token and status |
| 20 | SetState | Enable the listener state |

## Connect

The client creates a fresh 17-byte nonce:

```text
00 || Unix time in milliseconds (u64, big endian) || 8 random bytes
```

The activation RSA key signs the nonce with PKCS#1 v1.5 and SHA-1.

Connect fields used by this client:

| Field | Value |
|---:|---|
| 1 | Existing base token, only on reconnect |
| 2 | `01` |
| 5 | u32 `65`, big endian |
| 12 | Activation X.509 certificate in DER |
| 13 | Fresh nonce |
| 14 | `01 01 || RSA signature` |
| 16 | u16 `11`, big endian |

The server responds with type 8:

- field 1: one-byte status, zero on success;
- field 3: 32-byte base token when a fresh token is minted.

On a reconnect, the server may omit field 3; the supplied base token remains
valid.

## Scoped token

Request type 17:

| Field | Value |
|---:|---|
| 1 | Base token |
| 2 | SHA-1 of the UTF-8 topic string |

Response type 18:

- field 1: one-byte status;
- field 2: scoped token;
- field 3: topic SHA-1, which must match the request.

The resulting binary token can be registered with an external push provider.
Many providers represent it as lowercase hexadecimal.

## Subscribe

The client sends type 9 with the base token and topic SHA-1, then type 20 with
listener state and maximum state value `0x7fffffff`. A keepalive confirms the
session is usable before waiting for notifications.

## Notification and acknowledgement

Notification type 10:

- field 1: destination scoped token;
- field 2: topic SHA-1;
- field 3: JSON payload;
- field 4: message ID.

The client ignores unrelated frames, destination tokens, and topics. For a
matching notification it sends a type 11 receipt with:

- field 1: destination scoped token;
- field 4: message ID;
- field 8: one-byte success status.

No acknowledgement is sent when the destination or topic does not match.
