#!/usr/bin/env python3
"""Parse an Nmap XML report and print a network security summary.

Usage: python nmap_parser.py [XML_FILE]
Expected input: Nmap XML containing host status, addresses, and ports.
Expected output: host, service, exposure, and highest-risk summaries.
"""

from __future__ import annotations

import argparse
import ipaddress
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

ADMINISTRATIVE_PORTS = frozenset({22, 8089})
SMB_PORT = 445
RDP_PORT = 3389
WEB_PORTS = frozenset({80, 443})


@dataclass(frozen=True)
class OpenService:
    """Represent one open TCP or UDP service."""

    port: int
    protocol: str
    name: str


@dataclass(frozen=True)
class HostResult:
    """Represent the status and open services for one scanned host."""

    address: str
    status: str
    services: tuple[OpenService, ...]


def parse_port(port_element: ET.Element) -> OpenService | None:
    """Return an open service from a port element, or ``None``."""
    state = port_element.find("state")
    if state is None or state.get("state") != "open":
        return None

    port_text = port_element.get("portid")
    if port_text is None:
        return None
    try:
        port = int(port_text)
    except ValueError:
        return None

    service = port_element.find("service")
    name = "unknown"
    if service is not None:
        name = service.get("name", "unknown")
    return OpenService(
        port=port,
        protocol=port_element.get("protocol", "unknown"),
        name=name,
    )


def parse_host(host_element: ET.Element, position: int) -> HostResult:
    """Parse one Nmap host element into a concise result."""
    status_element = host_element.find("status")
    status = "unknown"
    if status_element is not None:
        status = status_element.get("state", "unknown")

    address_element = host_element.find("address[@addr]")
    address = f"unknown-host-{position}"
    if address_element is not None:
        address = address_element.get("addr", address)

    services = tuple(
        service
        for port_element in host_element.findall("./ports/port")
        if (service := parse_port(port_element)) is not None
    )
    return HostResult(address=address, status=status, services=services)


def parse_report(path: Path) -> list[HostResult]:
    """Parse all hosts from an Nmap XML report."""
    tree = ET.parse(path)
    return [
        parse_host(host_element, position)
        for position, host_element in enumerate(
            tree.getroot().findall("host"), start=1
        )
    ]


def hosts_exposing(
    hosts: Sequence[HostResult], ports: set[int] | frozenset[int]
) -> list[str]:
    """Return addresses of up hosts exposing any requested port."""
    return [
        host.address
        for host in hosts
        if host.status == "up"
        and any(service.port in ports for service in host.services)
    ]


def is_internal(address: str) -> bool:
    """Return whether an address is private according to ``ipaddress``."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def determine_risk(hosts: Sequence[HostResult]) -> str:
    """Return the highest observed risk level for the report."""
    smb_or_rdp = set(
        hosts_exposing(hosts, frozenset({SMB_PORT, RDP_PORT}))
    )
    if len(smb_or_rdp) > 3:
        return "CRITICAL"
    if smb_or_rdp:
        return "HIGH"

    administrative_hosts = hosts_exposing(hosts, ADMINISTRATIVE_PORTS)
    if any(not is_internal(address) for address in administrative_hosts):
        return "HIGH"
    if administrative_hosts:
        return "MEDIUM"
    return "LOW"


def format_host_list(addresses: Sequence[str]) -> str:
    """Format an address collection for compact summary output."""
    return ", ".join(addresses) if addresses else "None"


def format_summary(hosts: Sequence[HostResult]) -> str:
    """Build an executive-style summary from parsed Nmap host results."""
    up_hosts = [host for host in hosts if host.status == "up"]
    down_hosts = [host for host in hosts if host.status == "down"]
    services = [service for host in up_hosts for service in host.services]
    service_counts = Counter(service.name for service in services)

    smb_hosts = hosts_exposing(hosts, frozenset({SMB_PORT}))
    rdp_hosts = hosts_exposing(hosts, frozenset({RDP_PORT}))
    ssh_hosts = hosts_exposing(hosts, frozenset({22}))
    splunk_hosts = hosts_exposing(hosts, frozenset({8089}))
    web_hosts = hosts_exposing(hosts, WEB_PORTS)

    service_lines = [
        f"  {name}: {count}"
        for name, count in sorted(
            service_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ] or ["  None"]
    host_service_lines = [
        f"  {host.address}: "
        + ", ".join(
            f"{service.port}/{service.protocol} ({service.name})"
            for service in host.services
        )
        for host in up_hosts
        if host.services
    ] or ["  None"]

    lines = [
        "Network Security Assessment Summary",
        "===================================",
        f"Total hosts scanned: {len(hosts)}",
        f"Hosts up: {len(up_hosts)}",
        f"Hosts down: {len(down_hosts)}",
        f"Open ports: {len(services)}",
        f"Open services: {len(services)}",
        "",
        "Service frequency:",
        *service_lines,
        "",
        f"Hosts exposing SMB (445): {format_host_list(smb_hosts)}",
        f"Hosts exposing RDP (3389): {format_host_list(rdp_hosts)}",
        f"Hosts exposing SSH (22): {format_host_list(ssh_hosts)}",
        "Hosts exposing Splunk Management (8089): "
        f"{format_host_list(splunk_hosts)}",
        f"Hosts exposing HTTP/HTTPS: {format_host_list(web_hosts)}",
        f"Highest observed risk level: {determine_risk(hosts)}",
        "",
        "Open service detail:",
        *host_service_lines,
    ]
    return "\n".join(lines)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    default_report = Path(__file__).parent.parent / "sample-data" / "sample_nmap.xml"
    parser = argparse.ArgumentParser(
        description="Summarize an Nmap XML network security assessment."
    )
    parser.add_argument(
        "xml_file",
        nargs="?",
        type=Path,
        default=default_report,
        help=f"Nmap XML report to parse (default: {default_report})",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the Nmap parser and return a process exit code."""
    args = build_argument_parser().parse_args(argv)
    try:
        hosts = parse_report(args.xml_file)
    except FileNotFoundError:
        print(f"Error: XML file not found: {args.xml_file}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"Error: permission denied: {args.xml_file}", file=sys.stderr)
        return 1
    except ET.ParseError as exc:
        print(
            f"Error: malformed XML in {args.xml_file}: {exc}",
            file=sys.stderr,
        )
        return 1
    except OSError as exc:
        print(f"Error: could not read {args.xml_file}: {exc}", file=sys.stderr)
        return 1

    print(format_summary(hosts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
