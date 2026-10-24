#!/usr/bin/env python3
"""Send and receive a real, uniquely marked notification through Bark."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from apple_apns_courier import ActivationIdentity, CourierClient


DEFAULT_API = "https://api.day.app"
DEFAULT_TOPIC = "me.fin.bark"


def bark_post(api: str, path: str, body: dict, timeout: float) -> dict:
    if path not in ("/register", "/push"):
        raise ValueError("unexpected Bark API path")
    request = urllib.request.Request(
        api + path,
        data=json.dumps(body, separators=(",", ":")).encode(),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "apple-apns-courier-example/0.1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(65537)
            status = response.status
    except urllib.error.HTTPError as error:
        raw = error.read(65537)
        status = error.code
    if status != 200:
        raise RuntimeError(f"Bark {path} returned HTTP {status}")
    try:
        result = json.loads(raw)
    except Exception as error:
        raise RuntimeError(f"Bark {path} returned invalid JSON") from error
    if result.get("code") != 200:
        raise RuntimeError(
            f"Bark {path} failed with code {result.get('code')!r}"
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="End-to-end APNs Courier notification test through Bark"
    )
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument("--topic", default=DEFAULT_TOPIC)
    parser.add_argument("--api", default=DEFAULT_API)
    parser.add_argument("--timeout", default=25.0, type=float)
    parser.add_argument("--notification-timeout", default=45.0, type=float)
    args = parser.parse_args()

    run_id = uuid.uuid4().hex
    marker = "apple-apns-courier-" + run_id
    title = "APNs Courier test"
    body = "Bark end-to-end notification " + marker

    try:
        identity = ActivationIdentity.from_files(
            args.certificate,
            args.private_key,
        )
        with CourierClient.connect(
            identity,
            timeout=args.timeout,
            ca_file=args.ca_file,
        ) as client:
            scoped = client.request_scoped_token(args.topic)
            client.subscribe(args.topic)
            registration = bark_post(
                args.api,
                "/register",
                {"device_token": scoped.token.hex()},
                args.timeout,
            )
            device_key = registration.get("data", {}).get("device_key")
            if not device_key:
                raise RuntimeError("Bark registration returned no device_key")

            sent_at = time.perf_counter()
            bark_post(
                args.api,
                "/push",
                {
                    "device_key": device_key,
                    "title": title,
                    "body": body,
                    "level": "passive",
                    "group": "apple-apns-courier-example",
                },
                args.timeout,
            )
            notification = client.wait_for_notification(
                args.topic,
                scoped.token,
                timeout=args.notification_timeout,
            )
            elapsed_ms = round((time.perf_counter() - sent_at) * 1000, 2)

        alert = notification.payload.get("aps", {}).get("alert", {})
        checks = {
            "topic_matches": notification.topic == args.topic,
            "destination_matches": notification.destination == scoped.token,
            "title_matches": alert.get("title") == title,
            "body_matches": alert.get("body") == body,
            "marker_matches": marker in alert.get("body", ""),
            "ack_sent": bool(notification.message_id),
        }
        print(
            json.dumps(
                {
                    "run_id": run_id,
                    "topic": args.topic,
                    "scoped_token_sha256": hashlib.sha256(
                        scoped.token
                    ).hexdigest(),
                    "message_id": notification.message_id.hex(),
                    "payload_bytes": len(notification.raw_payload),
                    "payload_sha256": hashlib.sha256(
                        notification.raw_payload
                    ).hexdigest(),
                    "push_to_receive_ms": elapsed_ms,
                    "checks": checks,
                    "all_passed": all(checks.values()),
                    "secret_values_emitted": False,
                },
                indent=2,
            )
        )
        return 0 if all(checks.values()) else 1
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
