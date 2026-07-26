#!/usr/bin/env python3
"""Extract normalized indicators of compromise from security text.

Usage: python ioc_extractor.py [TEXT_FILE]
Expected input: unstructured UTF-8 incident or threat-hunting text.
Expected output: unique IOC counts and alphabetically sorted values.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)
EMAIL_PATTERN = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b",
    re.IGNORECASE,
)
DOMAIN_PATTERN = re.compile(
    r"\b(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|gov|edu|biz|info|example|test)\b",
    re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
MD5_PATTERN = re.compile(r"\b[A-F0-9]{32}\b", re.IGNORECASE)
SHA1_PATTERN = re.compile(r"\b[A-F0-9]{40}\b", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"\b[A-F0-9]{64}\b", re.IGNORECASE)
IP_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Z0-9_])[\[(]?[A-F0-9:.]{3,}[\])]?(?![A-Z0-9_])",
    re.IGNORECASE,
)
TRAILING_URL_PUNCTUATION = ".,;:!?)]}"


@dataclass(frozen=True)
class IOCSummary:
    """Contain normalized unique indicators grouped by IOC type."""

    ipv4: frozenset[str]
    ipv6: frozenset[str]
    domains: frozenset[str]
    urls: frozenset[str]
    emails: frozenset[str]
    cves: frozenset[str]
    md5: frozenset[str]
    sha1: frozenset[str]
    sha256: frozenset[str]

    @property
    def total(self) -> int:
        """Return the total number of unique typed indicators."""
        return sum(
            len(values)
            for values in (
                self.ipv4,
                self.ipv6,
                self.domains,
                self.urls,
                self.emails,
                self.cves,
                self.md5,
                self.sha1,
                self.sha256,
            )
        )


def mask_matches(text: str, patterns: Iterable[re.Pattern[str]]) -> str:
    """Replace matched spans with spaces while preserving text offsets."""
    masked = list(text)
    for pattern in patterns:
        for match in pattern.finditer(text):
            masked[match.start():match.end()] = " " * len(match.group())
    return "".join(masked)


def extract_ip_addresses(text: str) -> tuple[frozenset[str], frozenset[str]]:
    """Extract and canonicalize valid IPv4 and IPv6 candidates."""
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    for match in IP_CANDIDATE_PATTERN.finditer(text):
        candidate = match.group().strip("[](),.;")
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv4Address):
            ipv4.add(str(address))
        else:
            ipv6.add(address.compressed.lower())
    return frozenset(ipv4), frozenset(ipv6)


def extract_iocs(text: str) -> IOCSummary:
    """Extract supported IOC types from unstructured text."""
    urls = frozenset(
        match.group().rstrip(TRAILING_URL_PUNCTUATION)
        for match in URL_PATTERN.finditer(text)
    )
    emails = frozenset(
        match.group().lower() for match in EMAIL_PATTERN.finditer(text)
    )
    domain_text = mask_matches(text, (URL_PATTERN, EMAIL_PATTERN))
    domains = frozenset(
        match.group().lower() for match in DOMAIN_PATTERN.finditer(domain_text)
    )
    ipv4, ipv6 = extract_ip_addresses(text)

    return IOCSummary(
        ipv4=ipv4,
        ipv6=ipv6,
        domains=domains,
        urls=urls,
        emails=emails,
        cves=frozenset(
            match.group().upper() for match in CVE_PATTERN.finditer(text)
        ),
        md5=frozenset(
            match.group().lower() for match in MD5_PATTERN.finditer(text)
        ),
        sha1=frozenset(
            match.group().lower() for match in SHA1_PATTERN.finditer(text)
        ),
        sha256=frozenset(
            match.group().lower() for match in SHA256_PATTERN.finditer(text)
        ),
    )


def format_ioc_section(title: str, values: Iterable[str]) -> list[str]:
    """Format an IOC category with an alphabetical value list."""
    sorted_values = sorted(values, key=str.lower)
    lines = [f"{title}: {len(sorted_values)}"]
    lines.extend(f"  - {value}" for value in sorted_values)
    if not sorted_values:
        lines.append("  - None")
    return lines


def format_summary(summary: IOCSummary) -> str:
    """Build a SOC-style threat-hunting summary."""
    lines = [
        "Threat Hunting Summary",
        "======================",
        f"Total unique IOCs: {summary.total}",
        "",
        *format_ioc_section("IPv4 addresses", summary.ipv4),
        "",
        *format_ioc_section("IPv6 addresses", summary.ipv6),
        "",
        *format_ioc_section("Domains", summary.domains),
        "",
        *format_ioc_section("URLs", summary.urls),
        "",
        *format_ioc_section("Email addresses", summary.emails),
        "",
        *format_ioc_section("CVE identifiers", summary.cves),
        "",
        *format_ioc_section("MD5 hashes", summary.md5),
        "",
        *format_ioc_section("SHA1 hashes", summary.sha1),
        "",
        *format_ioc_section("SHA256 hashes", summary.sha256),
    ]
    return "\n".join(lines)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    default_report = Path(__file__).parent.parent / "sample-data" / "sample_incident_report.txt"
    parser = argparse.ArgumentParser(
        description="Extract IOCs from unstructured security text."
    )
    parser.add_argument(
        "text_file",
        nargs="?",
        type=Path,
        default=default_report,
        help=f"security text to analyze (default: {default_report})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the IOC extractor and return a process exit code."""
    args = build_argument_parser().parse_args(argv)
    try:
        text = args.text_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"Error: text file not found: {args.text_file}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: permission denied: {args.text_file}", file=sys.stderr)
        return 1
    except UnicodeDecodeError as exc:
        print(
            f"Error: {args.text_file} is not valid UTF-8: {exc}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(
            f"Error: could not read {args.text_file}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(format_summary(extract_iocs(text)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
