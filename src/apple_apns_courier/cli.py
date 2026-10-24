"""Command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from .client import APNsCourierError, CourierClient
from .identity import ActivationIdentity, IdentityError
from .storage import read_secret, save_token_state
from .transport import DEFAULT_HOST, DEFAULT_PORT


def _identity(args) -> ActivationIdentity:
    password = None
    if args.key_password_env:
        value = os.environ.get(args.key_password_env)
        if value is None:
            raise ValueError(
                f"environment variable {args.key_password_env} is not set"
            )
        password = value.encode()
    return ActivationIdentity.from_files(
        certificate_path=args.certificate,
        private_key_path=args.private_key,
        password=password,
    )


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--topic", required=True)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", default=DEFAULT_PORT, type=int)
    parser.add_argument("--timeout", default=20.0, type=float)
    parser.add_argument("--ca-file", type=Path)
    parser.add_argument(
        "--key-password-env",
        help="environment variable containing the private-key password",
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apple-apns-courier",
        description="Apple APNs Courier device client",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    token = subcommands.add_parser(
        "token",
        help="authenticate and request a topic-scoped token",
    )
    _common(token)
    token.add_argument(
        "--token-dir",
        required=True,
        type=Path,
        help="directory for the sensitive base and scoped token files",
    )

    listen = subcommands.add_parser(
        "listen",
        help="authenticate, subscribe, receive one notification, and ACK it",
    )
    _common(listen)
    listen.add_argument("--token-dir", required=True, type=Path)
    listen.add_argument(
        "--notification-timeout",
        default=120.0,
        type=float,
    )
    listen.add_argument("--save-notification", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        identity = _identity(args)
        if args.command == "token":
            with CourierClient.connect(
                identity,
                host=args.host,
                port=args.port,
                timeout=args.timeout,
                ca_file=args.ca_file,
            ) as client:
                tls = client.tls
                scoped = client.request_scoped_token(args.topic)
                metadata = save_token_state(
                    args.token_dir,
                    args.topic,
                    client.base_token,
                    scoped.token,
                )
            print(
                json.dumps(
                    {
                        "ok": True,
                        "action": "token",
                        "tls": asdict(tls),
                        "token_directory": str(args.token_dir),
                        **metadata,
                    },
                    indent=2,
                )
            )
            return 0

        base_token = read_secret(args.token_dir / "base-token.bin")
        scoped_token = read_secret(args.token_dir / "scoped-token.bin")
        with CourierClient.connect(
            identity,
            host=args.host,
            port=args.port,
            timeout=args.timeout,
            ca_file=args.ca_file,
            base_token=base_token,
        ) as client:
            client.subscribe(args.topic)
            print(
                json.dumps(
                    {
                        "ok": True,
                        "action": "listening",
                        "topic": args.topic,
                        "scoped_token_sha256": hashlib.sha256(
                            scoped_token
                        ).hexdigest(),
                    }
                ),
                flush=True,
            )
            notification = client.wait_for_notification(
                args.topic,
                scoped_token,
                timeout=args.notification_timeout,
            )
        if args.save_notification:
            args.save_notification.parent.mkdir(parents=True, exist_ok=True)
            args.save_notification.write_bytes(notification.raw_payload)
        print(
            json.dumps(
                {
                    "ok": True,
                    "action": "notification",
                    "topic": notification.topic,
                    "message_id": notification.message_id.hex(),
                    "payload_bytes": len(notification.raw_payload),
                    "payload_sha256": hashlib.sha256(
                        notification.raw_payload
                    ).hexdigest(),
                    "saved_to": (
                        str(args.save_notification)
                        if args.save_notification
                        else None
                    ),
                },
                indent=2,
            )
        )
        return 0
    except (IdentityError, APNsCourierError, TimeoutError, OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
