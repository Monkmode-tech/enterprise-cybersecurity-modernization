#!/usr/bin/env python3
"""Generate documented Splunk SPL searches for security detections.

Usage: python splunk_query_generator.py DETECTION_NAME
       python splunk_query_generator.py --list
Expected output: SPL, MITRE ATT&CK context, severity, and tuning notes.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class DetectionRule:
    """Represent one immutable Splunk detection-search definition."""

    key: str
    name: str
    purpose: str
    spl_query: str
    mitre_technique: str
    severity: str
    false_positives: str


DETECTION_RULES = (
    DetectionRule(
        key="failed_login",
        name="Windows Failed Login",
        purpose=(
            "Identify failed Windows authentication attempts for account "
            "monitoring and investigation."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Security" EventCode=4625 '
            "| stats count earliest(_time) AS first_seen "
            "latest(_time) AS last_seen BY src_ip, TargetUserName, host "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort - count"
        ),
        mitre_technique="T1110 - Brute Force",
        severity="Medium",
        false_positives=(
            "User password mistakes, expired credentials, service-account "
            "misconfiguration, and authentication health checks."
        ),
    ),
    DetectionRule(
        key="brute_force",
        name="Windows Brute-Force Authentication",
        purpose=(
            "Detect a high rate of failed Windows logins from one source "
            "within a short period."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Security" EventCode=4625 '
            "| bin _time span=5m "
            "| stats count dc(TargetUserName) AS targeted_accounts "
            "values(TargetUserName) AS accounts BY _time, src_ip "
            "| where count>=10 "
            "| sort - count"
        ),
        mitre_technique="T1110.001 - Password Guessing",
        severity="High",
        false_positives=(
            "Shared proxies, vulnerability assessments, misconfigured "
            "services, password changes, and approved penetration tests."
        ),
    ),
    DetectionRule(
        key="rdp_activity",
        name="Remote Desktop Logon Activity",
        purpose=(
            "Surface successful Remote Desktop logons for privileged-access "
            "review and source validation."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Security" EventCode=4624 '
            "Logon_Type=10 "
            "| stats count earliest(_time) AS first_seen "
            "latest(_time) AS last_seen BY src_ip, Account_Name, host "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort - last_seen"
        ),
        mitre_technique="T1021.001 - Remote Desktop Protocol",
        severity="Medium",
        false_positives=(
            "Approved help-desk support, jump-host administration, scheduled "
            "maintenance, and authorized third-party support."
        ),
    ),
    DetectionRule(
        key="ssh_activity",
        name="SSH Authentication Activity",
        purpose=(
            "Monitor accepted and failed SSH authentication for unexpected "
            "remote administration."
        ),
        spl_query=(
            'index=linux sourcetype="linux_secure" '
            '("Accepted password" OR "Accepted publickey" OR '
            '"Failed password") '
            '| rex field=_raw "for (?:invalid user )?(?<user>\\S+) from '
            '(?<src_ip>\\S+)" '
            "| stats count values(host) AS destinations "
            "values(_raw) AS events BY src_ip, user "
            "| sort - count"
        ),
        mitre_technique="T1021.004 - SSH",
        severity="Medium",
        false_positives=(
            "Approved Linux administration, automation accounts, deployment "
            "systems, vulnerability scans, and user typing errors."
        ),
    ),
    DetectionRule(
        key="powershell",
        name="PowerShell Script Execution",
        purpose=(
            "Identify PowerShell script-block activity for review of unusual "
            "commands and execution context."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Microsoft-Windows-'
            'PowerShell/Operational" EventCode=4104 '
            "| eval script=coalesce(ScriptBlockText, Message) "
            "| stats count values(script) AS scripts BY host, UserID "
            "| sort - count"
        ),
        mitre_technique="T1059.001 - PowerShell",
        severity="Medium",
        false_positives=(
            "Administrative scripts, software deployment, configuration "
            "management, login scripts, and approved troubleshooting."
        ),
    ),
    DetectionRule(
        key="encoded_powershell",
        name="Encoded PowerShell Execution",
        purpose=(
            "Detect PowerShell command lines containing encoded-command or "
            "hidden-execution indicators."
        ),
        spl_query=(
            'index=windows (sourcetype="XmlWinEventLog:Microsoft-Windows-'
            'Sysmon/Operational" EventCode=1) '
            '(Image="*\\\\powershell.exe" OR '
            'Image="*\\\\pwsh.exe") '
            '(CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" '
            'OR CommandLine="*FromBase64String*") '
            "| table _time, host, User, ParentImage, Image, CommandLine "
            "| sort - _time"
        ),
        mitre_technique="T1027 - Obfuscated Files or Information",
        severity="High",
        false_positives=(
            "Signed administrative tooling, deployment systems, security "
            "testing, and software that legitimately transports encoded data."
        ),
    ),
    DetectionRule(
        key="smb_activity",
        name="SMB Share Access Activity",
        purpose=(
            "Identify Windows network-share access for review of unusual "
            "sources, accounts, shares, and destinations."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Security" '
            "(EventCode=5140 OR EventCode=5145) "
            "| stats count values(ShareName) AS shares "
            "values(RelativeTargetName) AS targets BY src_ip, "
            "SubjectUserName, host "
            "| sort - count"
        ),
        mitre_technique="T1021.002 - SMB/Windows Admin Shares",
        severity="Medium",
        false_positives=(
            "File-server access, software distribution, backup operations, "
            "administrative shares, and vulnerability assessments."
        ),
    ),
    DetectionRule(
        key="malware_detection",
        name="Endpoint Malware Detection",
        purpose=(
            "Summarize endpoint malware alerts and response actions for SOC "
            "triage and containment validation."
        ),
        spl_query=(
            "index=endpoint (event_type=malware OR category=malware) "
            "| stats count values(file_name) AS files "
            "values(file_hash) AS hashes values(action) AS actions "
            "earliest(_time) AS first_seen latest(_time) AS last_seen "
            "BY host, user, severity "
            "| convert ctime(first_seen) ctime(last_seen) "
            "| sort - last_seen"
        ),
        mitre_technique="T1204.002 - Malicious File",
        severity="High",
        false_positives=(
            "Security test files, approved administration tools, software "
            "packers, development artifacts, and incorrect reputation data."
        ),
    ),
    DetectionRule(
        key="privilege_escalation",
        name="Windows Privilege Escalation Indicators",
        purpose=(
            "Detect special-privilege assignment and privileged-group changes "
            "that require authorization review."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:Security" '
            "(EventCode=4672 OR EventCode=4728 OR EventCode=4732) "
            "| eval account=coalesce(MemberName, SubjectUserName) "
            "| stats count values(EventCode) AS event_codes "
            "values(GroupName) AS groups BY host, account, SubjectUserName "
            "| sort - count"
        ),
        mitre_technique="T1098 - Account Manipulation",
        severity="High",
        false_positives=(
            "Approved administrator logons, identity lifecycle operations, "
            "service provisioning, and authorized emergency access."
        ),
    ),
    DetectionRule(
        key="new_service",
        name="New Windows Service Installation",
        purpose=(
            "Detect newly installed Windows services that may provide "
            "persistence or execute unauthorized software."
        ),
        spl_query=(
            'index=windows sourcetype="WinEventLog:System" EventCode=7045 '
            "| table _time, host, Service_Name, Service_File_Name, "
            "Service_Start_Type, Service_Account "
            "| sort - _time"
        ),
        mitre_technique="T1543.003 - Windows Service",
        severity="High",
        false_positives=(
            "Software installation, patching, endpoint agents, backup tools, "
            "driver packages, and approved service deployment."
        ),
    ),
    DetectionRule(
        key="firewall_blocks",
        name="Repeated Firewall Blocks",
        purpose=(
            "Identify sources generating repeated blocked connections that "
            "may indicate scanning or unauthorized access attempts."
        ),
        spl_query=(
            'index=firewall (action=blocked OR action=denied OR action=drop) '
            "| bin _time span=5m "
            "| stats count dc(dest_port) AS destination_ports "
            "values(dest_port) AS ports values(dest_ip) AS destinations "
            "BY _time, src_ip "
            "| where count>=20 OR destination_ports>=10 "
            "| sort - count"
        ),
        mitre_technique="T1046 - Network Service Discovery",
        severity="Medium",
        false_positives=(
            "Vulnerability scanners, monitoring systems, configuration "
            "errors, shared egress addresses, and approved security tests."
        ),
    ),
)

RULES_BY_KEY = {rule.key: rule for rule in DETECTION_RULES}


def valid_detection_names() -> list[str]:
    """Return all supported detection keys alphabetically."""
    return sorted(RULES_BY_KEY)


def format_valid_names() -> str:
    """Format valid detection names for CLI guidance."""
    return "\n".join(f"  - {name}" for name in valid_detection_names())


def format_rule(rule: DetectionRule) -> str:
    """Render one detection rule in the documented output format."""
    lines = [
        rule.name,
        "=" * len(rule.name),
        "",
        "Purpose",
        "-------",
        rule.purpose,
        "",
        "Splunk SPL Query",
        "----------------",
        rule.spl_query,
        "",
        "MITRE ATT&CK",
        "------------",
        rule.mitre_technique,
        "",
        "Recommended Alert Severity",
        "--------------------------",
        rule.severity,
        "",
        "False Positive Considerations",
        "-----------------------------",
        rule.false_positives,
    ]
    return "\n".join(lines)


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Generate a documented Splunk SPL detection search."
    )
    parser.add_argument(
        "detection",
        nargs="?",
        help="supported detection name",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list supported detection names alphabetically",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the query generator and return a process exit code."""
    args = build_argument_parser().parse_args(argv)

    if args.list:
        if args.detection is not None:
            print(
                "Error: --list cannot be combined with a detection name.",
                file=sys.stderr,
            )
            print("Valid detection names:", file=sys.stderr)
            print(format_valid_names(), file=sys.stderr)
            return 2
        print("Supported detections:")
        print(format_valid_names())
        return 0

    if args.detection is None:
        print(
            "Error: a detection name or --list is required.",
            file=sys.stderr,
        )
        print("Valid detection names:", file=sys.stderr)
        print(format_valid_names(), file=sys.stderr)
        return 2

    detection_key = args.detection.strip().lower()
    rule = RULES_BY_KEY.get(detection_key)
    if rule is None:
        print(
            f"Error: invalid detection name: {args.detection}",
            file=sys.stderr,
        )
        print("Valid detection names:", file=sys.stderr)
        print(format_valid_names(), file=sys.stderr)
        return 2

    print(format_rule(rule))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
