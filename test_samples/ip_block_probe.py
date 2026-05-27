#!/usr/bin/env python3
"""Benign IP-block validation probe.

This script helps verify that a server-side IP block, WAF rule, or firewall
rule is taking effect. It only sends ordinary HTTP(S) requests to one
explicitly provided URL and reports whether the response looks blocked.

Example:
    python test_samples/ip_block_probe.py https://example.com/health --count 10 --interval 1
"""

from __future__ import annotations

import argparse
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_BLOCKED_STATUSES = {401, 403, 407, 429}
MAX_COUNT = 200


@dataclass
class ProbeResult:
    attempt: int
    timestamp: str
    url: str
    method: str
    status: int | None
    blocked: bool
    elapsed_ms: int
    error: str | None


def parse_header(value: str) -> tuple[str, str]:
    if ":" not in value:
        raise argparse.ArgumentTypeError(
            f"Invalid header {value!r}; use 'Name: value' format."
        )
    name, header_value = value.split(":", 1)
    name = name.strip()
    header_value = header_value.strip()
    if not name:
        raise argparse.ArgumentTypeError("Header name cannot be empty.")
    return name, header_value


def parse_statuses(value: str) -> set[int]:
    statuses: set[int] = set()
    for raw_status in value.split(","):
        raw_status = raw_status.strip()
        if not raw_status:
            continue
        try:
            status = int(raw_status)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(
                f"Invalid HTTP status {raw_status!r}."
            ) from exc
        if status < 100 or status > 599:
            raise argparse.ArgumentTypeError(
                f"HTTP status must be between 100 and 599: {status}."
            )
        statuses.add(status)
    if not statuses:
        raise argparse.ArgumentTypeError("At least one blocked status is required.")
    return statuses


def validate_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise argparse.ArgumentTypeError("URL must start with http:// or https://.")
    return url


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_opener(insecure: bool) -> urllib.request.OpenerDirector:
    if not insecure:
        return urllib.request.build_opener()

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=context)
    return urllib.request.build_opener(https_handler)


def probe_once(
    opener: urllib.request.OpenerDirector,
    *,
    attempt: int,
    url: str,
    method: str,
    headers: dict[str, str],
    blocked_statuses: set[int],
    timeout: float,
) -> ProbeResult:
    started = time.perf_counter()
    request = urllib.request.Request(url, headers=headers, method=method)

    status: int | None = None
    error: str | None = None

    try:
        with opener.open(request, timeout=timeout) as response:
            status = response.status
    except urllib.error.HTTPError as exc:
        status = exc.code
    except (urllib.error.URLError, TimeoutError, socket.timeout, ConnectionError) as exc:
        error = f"{type(exc).__name__}: {exc}"

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    blocked = status in blocked_statuses or (status is None and error is not None)

    return ProbeResult(
        attempt=attempt,
        timestamp=utc_now(),
        url=url,
        method=method,
        status=status,
        blocked=blocked,
        elapsed_ms=elapsed_ms,
        error=error,
    )


def print_result(result: ProbeResult) -> None:
    status = str(result.status) if result.status is not None else "no-response"
    verdict = "BLOCKED" if result.blocked else "allowed"
    detail = f" error={result.error}" if result.error else ""
    print(
        f"[{result.attempt:03d}] {result.timestamp} "
        f"{result.method} {result.url} -> {status} {verdict} "
        f"({result.elapsed_ms} ms){detail}"
    )


def append_jsonl(path: Path, result: ProbeResult) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(asdict(result), ensure_ascii=True) + "\n")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Send safe HTTP(S) probes to validate an authorized server-side IP "
            "block or WAF rule."
        )
    )
    parser.add_argument("url", type=validate_url, help="Authorized target URL.")
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help=f"Number of requests to send. Default: 5. Maximum: {MAX_COUNT}.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds to wait between requests. Default: 1.0.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Per-request timeout in seconds. Default: 5.0.",
    )
    parser.add_argument(
        "--method",
        choices=("GET", "HEAD"),
        default="GET",
        help="HTTP method to use. Default: GET.",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        type=parse_header,
        metavar="'Name: value'",
        help="Additional request header. Can be repeated.",
    )
    parser.add_argument(
        "--blocked-statuses",
        type=parse_statuses,
        default=DEFAULT_BLOCKED_STATUSES,
        help="Comma-separated statuses considered blocked. Default: 401,403,407,429.",
    )
    parser.add_argument(
        "--marker",
        default="capstone-ip-block-test",
        help="Marker value added to User-Agent and X-Capstone-Test. Default: capstone-ip-block-test.",
    )
    parser.add_argument(
        "--jsonl",
        type=Path,
        help="Optional path for JSON Lines output.",
    )
    parser.add_argument(
        "--stop-on-block",
        action="store_true",
        help="Stop after the first blocked-looking response.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification for local test servers.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.count < 1 or args.count > MAX_COUNT:
        print(f"--count must be between 1 and {MAX_COUNT}.", file=sys.stderr)
        return 2
    if args.interval < 0:
        print("--interval must be 0 or greater.", file=sys.stderr)
        return 2
    if args.timeout <= 0:
        print("--timeout must be greater than 0.", file=sys.stderr)
        return 2

    headers = {
        "User-Agent": f"Capstone-IPBlock-Probe/1.0 ({args.marker})",
        "X-Capstone-Test": args.marker,
    }
    headers.update(dict(args.header))

    opener = build_opener(args.insecure)
    blocked_count = 0

    print("Benign IP block probe started.")
    print("Only run this against systems you own or are authorized to test.")
    print("This tool does not exploit, evade, persist, or spoof source IPs.")

    for attempt in range(1, args.count + 1):
        result = probe_once(
            opener,
            attempt=attempt,
            url=args.url,
            method=args.method,
            headers=headers,
            blocked_statuses=args.blocked_statuses,
            timeout=args.timeout,
        )
        blocked_count += int(result.blocked)
        print_result(result)

        if args.jsonl:
            append_jsonl(args.jsonl, result)

        if result.blocked and args.stop_on_block:
            break

        if attempt < args.count and args.interval > 0:
            time.sleep(args.interval)

    print(f"Summary: {blocked_count} blocked-looking response(s).")
    return 1 if blocked_count == 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
