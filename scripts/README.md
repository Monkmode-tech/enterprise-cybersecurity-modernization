# Security Log Parser

## Purpose

`log_parser.py` parses a structured security log and prints a concise summary for initial security review. It reports severity totals, source IP activity, authentication outcomes, and suspicious events while continuing past malformed entries. The utility uses only the Python standard library and is compatible with Python 3.12 or later.

## Usage

From the repository root, parse the included sample:

```text
python scripts/log_parser.py sample-data/sample.log
```

The sample file is used by default when no path is supplied:

```text
python scripts/log_parser.py
```

Display command-line help:

```text
python scripts/log_parser.py --help
```

## Sample Output

```text
Security Log Summary
====================
Total log entries: 55
INFO count: 26
WARNING count: 18
ERROR count: 11
Malformed entries skipped: 0
Unique source IP addresses: 15
Source IPs: 10.20.1.10, 10.20.1.11, 10.20.1.12, 10.20.1.13, 10.20.1.15, 10.20.1.77, 10.20.1.99, 10.20.2.25, 10.30.1.8, 10.30.1.9, 192.0.2.60, 198.51.100.20, 198.51.100.34, 203.0.113.45, 203.0.113.88
Top five source IPs:
  1. 203.0.113.45: 8
  2. 10.20.1.77: 5
  3. 192.0.2.60: 5
  4. 198.51.100.20: 4
  5. 10.20.2.25: 4
Authentication failures: 8
Successful logins: 9
Suspicious events: 29
```

## Assumptions

Each nonblank, noncomment line represents one event with this structure:

```text
ISO-8601-TIMESTAMP LEVEL event=EVENT_NAME src_ip=IP_ADDRESS message="DESCRIPTION"
```

- `LEVEL` must be `INFO`, `WARNING`, or `ERROR`.
- `event`, `src_ip`, and `message` are required.
- IPv4 and IPv6 source addresses are accepted.
- Quoted values may contain spaces.
- Authentication totals use the event names `auth_failure` and `auth_success`.
- Suspicious events are `auth_failure`, `firewall_block`, `ids_alert`, `malware_detection`, and `privilege_escalation`.
- Total log entries counts valid parsed events. Malformed entries are reported separately.

Malformed lines produce a warning with the line number and reason, then processing continues. A missing, unreadable, or inaccessible input file produces a clear error and a nonzero exit status.

## Limitations

- The parser accepts this documented format rather than arbitrary vendor log formats.
- Suspicious-event classification is a fixed event-name list, not behavioral detection or event correlation.
- The summary is printed to standard output and is not persisted.
- Source IP frequency is event volume, not an independent measure of risk.

---

# Nmap XML Parser

## Purpose

`nmap_parser.py` converts an Nmap XML report into a concise network security assessment summary. It reports host availability, open ports and services, service frequency, security-relevant port exposure, and the highest observed risk level. It uses only the Python standard library and supports Python 3.12 or later.

## Usage

Parse the included sample from the repository root:

```text
python scripts/nmap_parser.py sample-data/sample_nmap.xml
```

The sample report is used when no path is supplied:

```text
python scripts/nmap_parser.py
```

Display help with `python scripts/nmap_parser.py --help`.

## Sample Output

```text
Network Security Assessment Summary
===================================
Total hosts scanned: 10
Hosts up: 8
Hosts down: 2
Open ports: 18
Open services: 18

Service frequency:
  microsoft-ds: 3
  ms-wbt-server: 3
  ssh: 3
  http: 2
  https: 2
  msrpc: 2
  netbios-ssn: 2
  splunkd: 1

Hosts exposing SMB (445): 10.10.10.10, 10.10.10.11, 10.10.40.40
Hosts exposing RDP (3389): 10.10.10.10, 10.10.10.11, 10.10.40.41
Hosts exposing SSH (22): 10.10.20.20, 10.10.20.21, 10.10.30.30
Hosts exposing Splunk Management (8089): 10.10.30.30
Hosts exposing HTTP/HTTPS: 10.10.20.20, 10.10.20.21, 10.10.50.50
Highest observed risk level: CRITICAL
```

The utility then lists each up host and its open service details.

## Assumptions

- Input is Nmap XML containing host status, address, and port elements.
- Only ports with an `open` state are summarized.
- Ports 22, 445, 3389, and 8089 represent SSH, SMB, RDP, and Splunk Management.
- Ports 80 and 443 represent HTTP/HTTPS.
- SSH and Splunk Management are administrative services.
- Python's `ipaddress` module determines whether exposure is internal.
- A host exposing both SMB and RDP counts once toward the CRITICAL threshold.

Risk precedence is:

- `LOW`: no administrative services, SMB, or RDP are exposed.
- `MEDIUM`: administrative services are exposed only internally.
- `HIGH`: an administrative service is externally exposed, or SMB/RDP is exposed.
- `CRITICAL`: more than three distinct hosts expose SMB or RDP.

## Limitations

- The parser summarizes an existing report; it does not perform a scan.
- Risk considers addresses and open ports, not authentication, compensating controls, vulnerabilities, or business criticality.
- Missing service names appear as `unknown`.
- Optional Nmap XML elements outside the required summary are not parsed.
- Output is printed to standard output and is not persisted.

---

# Nessus Vulnerability Summary

## Purpose

`vulnerability_summary.py` converts a Nessus-style CSV into an executive remediation report for security analysts and IT leadership. It summarizes severity, affected hosts, common vulnerability categories, CVSS values, high-risk service exposure, and remediation priorities. The utility uses only the Python standard library and supports Python 3.12 or later.

## Usage

Parse the included sample from the repository root:

```text
python scripts/vulnerability_summary.py sample-data/sample_nessus.csv
```

The sample report is used when no path is supplied:

```text
python scripts/vulnerability_summary.py
```

Display help with `python scripts/vulnerability_summary.py --help`.

## Sample Output

```text
Executive Vulnerability Summary
===============================
Total findings: 50
Critical findings: 7
High findings: 14
Medium findings: 11
Low findings: 9
Informational findings: 9
Malformed rows skipped: 0
Affected hosts: 10
Highest observed CVSS: 10.0
Average CVSS: 5.44

Most vulnerable hosts (Top 5):
  1. 10.10.10.10: 5 findings
  2. 10.10.10.11: 5 findings
  3. 10.10.20.20: 5 findings
  4. 10.10.20.21: 5 findings
  5. 10.10.30.30: 5 findings

Most common vulnerability categories:
  1. Web Security: 12
  2. RDP Security: 8
  3. SSH Security: 7
  4. SMB Security: 6
  5. Information Disclosure: 5

High-risk exposed services:
  SSH (22): 10.10.20.20, 10.10.60.60
  HTTP (80): 10.10.60.61
  HTTPS (443): 10.10.20.21, 10.10.50.50
  SMB (445): 10.10.10.10, 10.10.10.11, 10.10.40.40
  RDP (3389): 10.10.10.10, 10.10.10.11, 10.10.40.41
  Splunk (8089): 10.10.30.30

Recommended remediation priorities:
  Priority 1 - Critical vulnerabilities: 7
  Priority 2 - High vulnerabilities on exposed services: 12
  Priority 3 - Remaining High vulnerabilities: 2
  Priority 4 - Medium vulnerabilities: 11
  Priority 5 - Low and Informational findings: 18

Remediation direction:
  1. Address Critical findings immediately and validate closure.
  2. Restrict and remediate High-risk exposed services.
  3. Patch remaining High and Medium findings by risk order.
  4. Track Low and Informational findings through governance.
```

## Assumptions

- Input uses the columns `Host`, `Plugin ID`, `Plugin Name`, `Severity`, `CVSS`, `Port`, `Protocol`, and `Synopsis`.
- Supported severity values are Critical, High, Medium, Low, Info, and Informational.
- CVSS values range from 0.0 through 10.0, and ports range from 0 through 65535.
- Ports 22, 80, 443, 445, 3389, and 8089 represent SSH, HTTP, HTTPS, SMB, RDP, and Splunk.
- Because the CSV has no network-zone field, findings on those six ports are treated as exposed-service findings for Priority 2.
- Vulnerability categories are derived from plugin names and service ports.
- Every valid CSV row represents one finding; malformed rows are warned about and skipped.

The remediation model is:

- `Priority 1`: Critical vulnerabilities.
- `Priority 2`: High vulnerabilities on exposed services.
- `Priority 3`: remaining High vulnerabilities.
- `Priority 4`: Medium vulnerabilities.
- `Priority 5`: Low and Informational findings.

## Limitations

- The utility summarizes an exported report and does not perform a Nessus scan.
- Port-based exposure is a prioritization proxy, not proof of Internet reachability.
- The model does not include asset criticality, exploit activity, compensating controls, or remediation age.
- Category assignment uses concise keyword and port rules rather than Nessus plugin families.
- Duplicate CSV rows are counted as separate findings.
- Output is printed to standard output and is not persisted.

---

# Enterprise Risk Calculator

## Purpose

`risk_calculator.py` combines asset criticality, vulnerability severity, Internet exposure, exploit availability, and CVSS into a weighted enterprise risk score. It ranks assets for remediation and presents the portfolio-level distribution in an executive consulting format. The utility uses only the Python standard library and supports Python 3.12 or later.

## Usage

Evaluate the included samples from the repository root:

```text
python scripts/risk_calculator.py sample-data/sample_assets.csv sample-data/sample_findings.csv
```

Both sample files are used when no paths are supplied:

```text
python scripts/risk_calculator.py
```

Display help with `python scripts/risk_calculator.py --help`.

## Sample Output

```text
Enterprise Risk Assessment
==========================
Assets evaluated: 10
Average risk score: 15.37
Highest risk asset: Customer Portal - 17.9 (Critical)
Malformed asset rows skipped: 0
Malformed finding rows skipped: 0
Findings with unknown assets skipped: None

Top five highest-risk assets:
  1. Customer Portal: 17.9 (Critical, 5 findings)
  2. Public Web Server: 17.9 (Critical, 5 findings)
  3. Domain Controller 1: 16.9 (Critical, 5 findings)
  4. Windows File Server: 15.9 (Critical, 5 findings)
  5. Administrative Jump Host: 15.4 (Critical, 5 findings)

Risk distribution:
  Critical: 6
  High: 3
  Medium: 1
  Low: 0

Recommended remediation order:
  1. Customer Portal - Critical (17.9); address Critical finding
  2. Public Web Server - Critical (17.9); address Critical finding
  3. Domain Controller 1 - Critical (16.9); address Critical finding
  4. Windows File Server - Critical (15.9); address Critical finding
  5. Administrative Jump Host - Critical (15.4); address High finding
  6. Domain Controller 2 - Critical (15.4); address High finding
  7. Database Server - High (14.9); address Critical finding
  8. Splunk Server - High (14.1); address High finding
  9. Linux Application Server - High (14.1); address High finding
  10. Internal Application Server - Medium (11.2); address Medium finding
```

## Assumptions

- The asset CSV contains `Asset`, `Business Criticality`, and `Internet Facing`.
- The findings CSV contains `Asset`, `Severity`, `CVSS`, and `Exploit Available`.
- Asset names provide the exact relationship between the two files.
- Criticality supports Critical, High, Medium, and Low; severity additionally supports Informational.
- Internet Facing and Exploit Available accept Yes or No.
- CVSS values must be between 0.0 and 10.0.
- Each finding is scored with the documented weighted formula.
- An asset's overall score is its highest finding score, preventing finding volume alone from inflating risk.
- An asset without findings receives its criticality weight as a baseline and is flagged for coverage validation.
- Findings naming assets absent from the inventory are skipped and reported.

The score is:

```text
Business Criticality + Severity + Internet Exposure
+ Exploitability + (CVSS / 2)
```

Classifications are Critical at 15 or above, High at 12 or above, Medium at 8 or above, and Low below 8.

## Limitations

- The model is a transparent prioritization aid, not a quantitative forecast of financial loss.
- The highest-finding aggregation emphasizes the most urgent condition rather than cumulative exposure.
- Internet exposure and exploit availability are binary inputs and do not measure control effectiveness or exploit maturity.
- Asset dependencies, compensating controls, remediation age, and threat intelligence are outside this model.
- Duplicate asset names are rejected; duplicate findings are scored independently.
- Output is printed to standard output and is not persisted.

---

# IOC Extractor

## Purpose

`ioc_extractor.py` extracts and normalizes common Indicators of Compromise from unstructured incident reports, analyst notes, alerts, and threat-intelligence text. It produces a deduplicated SOC-style hunting summary for IPv4, IPv6, domains, URLs, email addresses, CVE identifiers, and MD5, SHA1, and SHA256 hashes. The utility uses only the Python standard library and supports Python 3.12 or later.

## Usage

Analyze the included incident report from the repository root:

```text
python scripts/ioc_extractor.py sample-data/sample_incident_report.txt
```

The sample report is used when no path is supplied:

```text
python scripts/ioc_extractor.py
```

Display help with `python scripts/ioc_extractor.py --help`.

## Sample Output

```text
Threat Hunting Summary
======================
Total unique IOCs: 27

IPv4 addresses: 5
  - 10.20.1.77
  - 10.30.1.8
  - 192.0.2.60
  - 198.51.100.77
  - 203.0.113.45

IPv6 addresses: 2
  - 2001:db8:85a3::8a2e:370:7334
  - 2001:db8:abcd:12::44

Domains: 5
  - cdn-cache.example
  - login-review.example
  - secure-docs.example
  - telemetry-node.test
  - update-check.example

URLs: 3
  - http://198.51.100.77:8080/stage.ps1
  - https://secure-docs.example/invoice/Review.zip
  - https://update-check.example/api/v2/beacon

Email addresses: 3
  - billing-alert@secure-docs.example
  - helpdesk-review@ficbank.example
  - soc@ficbank.example

CVE identifiers: 3
  - CVE-2021-44228
  - CVE-2023-23397
  - CVE-2024-3094

MD5 hashes: 2
  - 44d88612fea8a8f36de82e1278abb02f
  - d41d8cd98f00b204e9800998ecf8427e

SHA1 hashes: 2
  - 3395856ce81f2b7382dee72602f798b642f14140
  - da39a3ee5e6b4b0d3255bfef95601890afd80709

SHA256 hashes: 2
  - 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  - e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

## Assumptions

- Input is unstructured UTF-8 text.
- IPv4 and IPv6 candidates are validated and canonicalized with `ipaddress`.
- Domains and email addresses are normalized to lowercase.
- CVE identifiers are normalized to uppercase; hashes are lowercase.
- URLs retain their observed case while trailing sentence punctuation is removed.
- IOC values are deduplicated within each type and listed alphabetically.
- Domain matching recognizes conventional and reserved sample top-level domains.
- URL and email spans are excluded from standalone-domain matching, preventing automatic duplication of their domain components.
- Total unique IOCs is the sum of unique values across the nine supported types.

## Limitations

- Pattern matching identifies syntactically plausible indicators; it does not determine whether they are malicious.
- Obfuscated indicators such as `hxxp`, `[.]`, defanged email addresses, and encoded values are not expanded.
- Internationalized domain names and uncommon top-level domains may require additional normalization or pattern coverage.
- URLs are extracted as observed and are not fetched, resolved, or reputation-checked.
- Hash type is inferred from hexadecimal length rather than file metadata.
- The utility does not perform event correlation or preserve source-line provenance.
- Output is printed to standard output and is not persisted.

---

# Splunk Query Generator

## Purpose

`splunk_query_generator.py` generates documented Splunk SPL detection searches for common enterprise security use cases. Every rule includes its purpose, SPL, MITRE ATT&CK mapping, recommended alert severity, and false-positive considerations. The standard-library utility provides a consistent starting point for detection engineering without claiming live deployment or validation.

## Usage

Generate one detection from the repository root:

```text
python scripts/splunk_query_generator.py failed_login
```

List every supported detection alphabetically:

```text
python scripts/splunk_query_generator.py --list
```

Display command-line help with `python scripts/splunk_query_generator.py --help`.

An invalid name returns a clear error, the valid-name list, and exit code 2.

## Supported Detections

- `brute_force`
- `encoded_powershell`
- `failed_login`
- `firewall_blocks`
- `malware_detection`
- `new_service`
- `powershell`
- `privilege_escalation`
- `rdp_activity`
- `smb_activity`
- `ssh_activity`

## Sample Output

```text
Windows Failed Login
====================

Purpose
-------
Identify failed Windows authentication attempts for account monitoring and investigation.

Splunk SPL Query
----------------
index=windows sourcetype="WinEventLog:Security" EventCode=4625 | stats count earliest(_time) AS first_seen latest(_time) AS last_seen BY src_ip, TargetUserName, host | convert ctime(first_seen) ctime(last_seen) | sort - count

MITRE ATT&CK
------------
T1110 - Brute Force

Recommended Alert Severity
--------------------------
Medium

False Positive Considerations
-----------------------------
User password mistakes, expired credentials, service-account misconfiguration, and authentication health checks.
```

## Assumptions

- Splunk indexes such as `windows`, `linux`, `endpoint`, and `firewall` are placeholders for local data routing.
- Windows detections expect common event codes and conventional Windows or Sysmon fields.
- Linux SSH detection expects `linux_secure`-style message content.
- Endpoint and firewall searches expect normalized action, address, user, file, and severity fields.
- Threshold searches use starting values that must be tuned to environment baselines.
- MITRE ATT&CK mappings describe the principal behavior represented by each search.
- Recommended severity is initial guidance and does not replace asset or identity context.

## Limitations

- The searches were not tested against a live Splunk deployment.
- SPL field names, sourcetypes, indexes, and data-model mappings vary by environment.
- Each query requires validation against available telemetry, data quality, retention, and time-zone handling.
- Allowlisting and threshold tuning are required before enabling production alerts.
- Individual searches do not provide complete detection coverage or prove malicious activity.
- The utility prints rules to standard output and does not create saved searches, alerts, or Splunk configuration files.
