#!/usr/bin/env python3
"""Parse structured security logs and print a concise security summary.

Usage: python log_parser.py [LOG_FILE]
Expected input: one event per line in the format documented in README.md.
Expected output: severity, source IP, and security event totals.
"""

from __future__ import annotations

import argparse
import ipaddress
import shlex
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Sequence, TextIO

VALID_LEVELS = frozenset({"INFO", "WARNING", "ERROR"})
SUSPICIOUS_EVENTS = frozenset(
    {
        "auth_failure",
        "firewall_block",
        "ids_alert",
        "malware_detection",
        "privilege_escalation",
    }
)


class LogParseError(ValueError):
    """Represent a malformed security log entry."""


@dataclass(frozen=True)
class LogEntry:
    """Represent the fields used to summarize one valid log entry."""

    timestamp: datetime
    level: str
    event: str
    source_ip: str
    message: str


@dataclass(frozen=True)
class ParseResult:
    """Contain valid entries and the number of malformed lines skipped."""

    entries: list[LogEntry]
    malformed_count: int


def parse_timestamp(value: str) -> datetime:
    """Parse an ISO 8601 timestamp, including the ``Z`` UTC suffix."""
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise LogParseError(f"invalid timestamp {value!r}") from exc


def parse_fields(raw_fields: str) -> dict[str, str]:
    """Parse shell-like ``key=value`` fields from a log entry."""
    try:
        tokens = shlex.split(raw_fields)
    except ValueError as exc:
        raise LogParseError(f"invalid quoted field: {exc}") from exc

    fields: dict[str, str] = {}
    for token in tokens:
        if "=" not in token:
            raise LogParseError(f"expected key=value field, found {token!r}")
        key, value = token.split("=", 1)
        if not key or not value:
            raise LogParseError(f"empty key or value in field {token!r}")
        fields[key] = value
    return fields


def parse_line(line: str) -> LogEntry:
    """Parse and validate one structured security log line."""
    parts = line.split(maxsplit=2)
    if len(parts) != 3:
        raise LogParseError("expected timestamp, level, and event fields")

    timestamp_text, level, raw_fields = parts
    if level not in VALID_LEVELS:
        raise LogParseError(f"unsupported level {level!r}")

    fields = parse_fields(raw_fields)
    missing = {"event", "src_ip", "message"} - fields.keys()
    if missing:
        names = ", ".join(sorted(missing))
        raise LogParseError(f"missing required field(s): {names}")

    try:
        source_ip = str(ipaddress.ip_address(fields["src_ip"]))
    except ValueError as exc:
        raise LogParseError(
            f"invalid source IP address {fields['src_ip']!r}"
        ) from exc

    return LogEntry(
        timestamp=parse_timestamp(timestamp_text),
        level=level,
        event=fields["event"],
        source_ip=source_ip,
        message=fields["message"],
    )


def parse_log(path: Path, error_stream: TextIO = sys.stderr) -> ParseResult:
    """Read a log file, skipping blank, comment, and malformed lines."""
    entries: list[LogEntry] = []
    malformed_count = 0

    with path.open(encoding="utf-8") as log_file:
        for line_number, raw_line in enumerate(log_file, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entries.append(parse_line(line))
            except LogParseError as exc:
                malformed_count += 1
                print(
                    f"Warning: skipped malformed line {line_number}: {exc}",
                    file=error_stream,
                )

    return ParseResult(entries=entries, malformed_count=malformed_count)


def format_summary(result: ParseResult) -> str:
    """Build a human-readable security summary from parsed entries."""
    level_counts = Counter(entry.level for entry in result.entries)
    source_counts = Counter(entry.source_ip for entry in result.entries)
    event_counts = Counter(entry.event for entry in result.entries)
    suspicious_count = sum(
        count
        for event, count in event_counts.items()
        if event in SUSPICIOUS_EVENTS
    )

    unique_sources = ", ".join(sorted(source_counts)) or "None"
    top_sources = source_counts.most_common(5)
    top_lines = [
        f"  {position}. {source_ip}: {count}"
        for position, (source_ip, count) in enumerate(top_sources, start=1)
    ] or ["  None"]

    lines = [
        "Security Log Summary",
        "====================",
        f"Total log entries: {len(result.entries)}",
        f"INFO count: {level_counts['INFO']}",
        f"WARNING count: {level_counts['WARNING']}",
        f"ERROR count: {level_counts['ERROR']}",
        f"Malformed entries skipped: {result.malformed_count}",
        f"Unique source IP addresses: {len(source_counts)}",
        f"Source IPs: {unique_sources}",
        "Top five source IPs:",
        *top_lines,
        f"Authentication failures: {event_counts['auth_failure']}",
        f"Successful logins: {event_counts['auth_success']}",
        f"Suspicious events: {suspicious_count}",
    ]
    return "\n".join(lines)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    default_log = Path(__file__).parent.parent / "sample-data" / "sample.log"
    parser = argparse.ArgumentParser(
        description="Parse a structured security log and print a summary."
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        type=Path,
        default=default_log,
        help=f"log file to parse (default: {default_log})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line utility and return a process exit code."""
    args = build_argument_parser().parse_args(argv)
    try:
        result = parse_log(args.log_file)
    except FileNotFoundError:
        print(f"Error: log file not found: {args.log_file}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: permission denied: {args.log_file}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: could not read {args.log_file}: {exc}", file=sys.stderr)
        return 1

    print(format_summary(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
