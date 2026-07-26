#!/usr/bin/env python3
"""Calculate weighted enterprise risk from asset and finding CSV files.

Usage: python risk_calculator.py [ASSETS_CSV] [FINDINGS_CSV]
Expected input: CSV schemas documented in scripts/README.md.
Expected output: asset rankings, risk distribution, and remediation order.
"""

from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence, TextIO

CRITICALITY_WEIGHTS = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
}
SEVERITY_WEIGHTS = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}
YES_NO_VALUES = {"yes": True, "no": False}
ASSET_COLUMNS = frozenset(
    {"Asset", "Business Criticality", "Internet Facing"}
)
FINDING_COLUMNS = frozenset(
    {"Asset", "Severity", "CVSS", "Exploit Available"}
)


class CsvInputError(ValueError):
    """Represent invalid CSV structure or field content."""


@dataclass(frozen=True)
class Asset:
    """Represent an enterprise asset and its business context."""

    name: str
    criticality: str
    internet_facing: bool


@dataclass(frozen=True)
class Finding:
    """Represent a vulnerability finding used in risk scoring."""

    asset_name: str
    severity: str
    cvss: float
    exploit_available: bool


@dataclass(frozen=True)
class AssetRisk:
    """Represent the calculated risk result for one asset."""

    asset: Asset
    score: float
    classification: str
    finding_count: int
    driving_finding: Finding | None


@dataclass(frozen=True)
class ParsedRows:
    """Contain valid rows and the count of malformed rows skipped."""

    rows: list[Asset | Finding]
    malformed_count: int


def require_value(row: dict[str, str | None], column: str) -> str:
    """Return a required nonblank CSV value."""
    value = row.get(column)
    if value is None or not value.strip():
        raise CsvInputError(f"missing value for {column!r}")
    return value.strip()


def normalize_choice(
    value: str, choices: dict[str, int], field_name: str
) -> str:
    """Normalize a value against a case-insensitive choice mapping."""
    normalized = value.strip().title()
    if normalized not in choices:
        expected = ", ".join(choices)
        raise CsvInputError(
            f"invalid {field_name} {value!r}; expected {expected}"
        )
    return normalized


def parse_yes_no(value: str, field_name: str) -> bool:
    """Parse a Yes or No field into a boolean."""
    normalized = value.strip().lower()
    if normalized not in YES_NO_VALUES:
        raise CsvInputError(
            f"invalid {field_name} {value!r}; expected Yes or No"
        )
    return YES_NO_VALUES[normalized]


def parse_asset(row: dict[str, str | None]) -> Asset:
    """Validate and convert one asset CSV row."""
    name = require_value(row, "Asset")
    criticality = normalize_choice(
        require_value(row, "Business Criticality"),
        CRITICALITY_WEIGHTS,
        "Business Criticality",
    )
    internet_facing = parse_yes_no(
        require_value(row, "Internet Facing"), "Internet Facing"
    )
    return Asset(
        name=name,
        criticality=criticality,
        internet_facing=internet_facing,
    )


def parse_finding(row: dict[str, str | None]) -> Finding:
    """Validate and convert one finding CSV row."""
    asset_name = require_value(row, "Asset")
    severity = normalize_choice(
        require_value(row, "Severity"),
        SEVERITY_WEIGHTS,
        "Severity",
    )
    try:
        cvss = float(require_value(row, "CVSS"))
    except ValueError as exc:
        raise CsvInputError("CVSS must be numeric") from exc
    if not 0.0 <= cvss <= 10.0:
        raise CsvInputError("CVSS must be between 0.0 and 10.0")
    exploit_available = parse_yes_no(
        require_value(row, "Exploit Available"), "Exploit Available"
    )
    return Finding(
        asset_name=asset_name,
        severity=severity,
        cvss=cvss,
        exploit_available=exploit_available,
    )


def read_csv_rows(
    path: Path,
    required_columns: frozenset[str],
    row_parser: Callable[[dict[str, str | None]], Asset | Finding],
    error_stream: TextIO = sys.stderr,
) -> ParsedRows:
    """Read, validate, and defensively parse a supported CSV file."""
    parsed_rows: list[Asset | Finding] = []
    malformed_count = 0

    with path.open(encoding="utf-8-sig", newline="") as csv_file:
        reader = csv.DictReader(csv_file, strict=True)
        if reader.fieldnames is None:
            raise CsvInputError("CSV header is missing")
        missing_columns = required_columns - set(reader.fieldnames)
        if missing_columns:
            missing = ", ".join(sorted(missing_columns))
            raise CsvInputError(f"missing required column(s): {missing}")

        for line_number, row in enumerate(reader, start=2):
            if None in row:
                malformed_count += 1
                print(
                    f"Warning: skipped malformed row {line_number} in "
                    f"{path}: too many fields",
                    file=error_stream,
                )
                continue
            try:
                parsed_rows.append(row_parser(row))
            except CsvInputError as exc:
                malformed_count += 1
                print(
                    f"Warning: skipped malformed row {line_number} in "
                    f"{path}: {exc}",
                    file=error_stream,
                )

    return ParsedRows(parsed_rows, malformed_count)


def calculate_finding_score(asset: Asset, finding: Finding) -> float:
    """Calculate the weighted score for one asset-finding pair."""
    return (
        CRITICALITY_WEIGHTS[asset.criticality]
        + SEVERITY_WEIGHTS[finding.severity]
        + (2 if asset.internet_facing else 0)
        + (2 if finding.exploit_available else 0)
        + (finding.cvss / 2)
    )


def classify_risk(score: float) -> str:
    """Classify a weighted risk score using the required thresholds."""
    if score >= 15:
        return "Critical"
    if score >= 12:
        return "High"
    if score >= 8:
        return "Medium"
    return "Low"


def calculate_asset_risks(
    assets: Sequence[Asset], findings: Sequence[Finding]
) -> tuple[list[AssetRisk], list[str]]:
    """Calculate one highest-observed risk result per asset."""
    assets_by_name = {asset.name: asset for asset in assets}
    findings_by_asset: dict[str, list[Finding]] = defaultdict(list)
    unknown_assets: set[str] = set()
    for finding in findings:
        if finding.asset_name not in assets_by_name:
            unknown_assets.add(finding.asset_name)
            continue
        findings_by_asset[finding.asset_name].append(finding)

    results: list[AssetRisk] = []
    for asset in assets:
        asset_findings = findings_by_asset[asset.name]
        scored_findings = [
            (calculate_finding_score(asset, finding), finding)
            for finding in asset_findings
        ]
        score, driver = max(
            scored_findings,
            key=lambda item: item[0],
            default=(float(CRITICALITY_WEIGHTS[asset.criticality]), None),
        )
        results.append(
            AssetRisk(
                asset=asset,
                score=score,
                classification=classify_risk(score),
                finding_count=len(asset_findings),
                driving_finding=driver,
            )
        )
    results.sort(key=lambda result: (-result.score, result.asset.name))
    return results, sorted(unknown_assets)


def format_summary(
    risks: Sequence[AssetRisk],
    malformed_assets: int,
    malformed_findings: int,
    unknown_assets: Sequence[str],
) -> str:
    """Build an executive-style enterprise risk assessment."""
    average_score = (
        sum(result.score for result in risks) / len(risks) if risks else 0.0
    )
    distribution = Counter(result.classification for result in risks)
    highest = risks[0] if risks else None

    top_lines = [
        f"  {position}. {result.asset.name}: {result.score:.1f} "
        f"({result.classification}, {result.finding_count} findings)"
        for position, result in enumerate(risks[:5], start=1)
    ] or ["  None"]
    remediation_lines = [
        f"  {position}. {result.asset.name} - {result.classification} "
        f"({result.score:.1f}); address {result.driving_finding.severity} "
        "finding"
        if result.driving_finding is not None
        else (
            f"  {position}. {result.asset.name} - no findings; "
            "validate coverage"
        )
        for position, result in enumerate(risks, start=1)
    ] or ["  None"]

    highest_text = "None"
    if highest is not None:
        highest_text = (
            f"{highest.asset.name} - {highest.score:.1f} "
            f"({highest.classification})"
        )
    unknown_text = ", ".join(unknown_assets) if unknown_assets else "None"

    lines = [
        "Enterprise Risk Assessment",
        "==========================",
        f"Assets evaluated: {len(risks)}",
        f"Average risk score: {average_score:.2f}",
        f"Highest risk asset: {highest_text}",
        f"Malformed asset rows skipped: {malformed_assets}",
        f"Malformed finding rows skipped: {malformed_findings}",
        f"Findings with unknown assets skipped: {unknown_text}",
        "",
        "Top five highest-risk assets:",
        *top_lines,
        "",
        "Risk distribution:",
        f"  Critical: {distribution['Critical']}",
        f"  High: {distribution['High']}",
        f"  Medium: {distribution['Medium']}",
        f"  Low: {distribution['Low']}",
        "",
        "Recommended remediation order:",
        *remediation_lines,
    ]
    return "\n".join(lines)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    sample_directory = Path(__file__).parent.parent / "sample-data"
    parser = argparse.ArgumentParser(
        description="Calculate weighted enterprise cyber risk by asset."
    )
    parser.add_argument(
        "assets_csv",
        nargs="?",
        type=Path,
        default=sample_directory / "sample_assets.csv",
        help="asset inventory CSV",
    )
    parser.add_argument(
        "findings_csv",
        nargs="?",
        type=Path,
        default=sample_directory / "sample_findings.csv",
        help="vulnerability findings CSV",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the risk calculator and return a process exit code."""
    args = build_argument_parser().parse_args(argv)
    try:
        asset_rows = read_csv_rows(
            args.assets_csv, ASSET_COLUMNS, parse_asset
        )
        finding_rows = read_csv_rows(
            args.findings_csv, FINDING_COLUMNS, parse_finding
        )
    except FileNotFoundError as exc:
        print(f"Error: CSV file not found: {exc.filename}", file=sys.stderr)
        return 1
    except PermissionError as exc:
        print(f"Error: permission denied: {exc.filename}", file=sys.stderr)
        return 1
    except (csv.Error, CsvInputError) as exc:
        print(f"Error: malformed CSV: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error: could not read CSV input: {exc}", file=sys.stderr)
        return 1

    assets = [row for row in asset_rows.rows if isinstance(row, Asset)]
    findings = [
        row for row in finding_rows.rows if isinstance(row, Finding)
    ]
    duplicate_names = [
        name for name, count in Counter(asset.name for asset in assets).items()
        if count > 1
    ]
    if duplicate_names:
        duplicates = ", ".join(sorted(duplicate_names))
        print(f"Error: duplicate asset name(s): {duplicates}", file=sys.stderr)
        return 1

    risks, unknown_assets = calculate_asset_risks(assets, findings)
    print(
        format_summary(
            risks,
            asset_rows.malformed_count,
            finding_rows.malformed_count,
            unknown_assets,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
