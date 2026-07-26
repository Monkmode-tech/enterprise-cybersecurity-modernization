# Enterprise Cybersecurity Modernization

## Executive Summary

This portfolio presents a cybersecurity consulting case study for **FICBANK, a fictional mid-sized financial institution**. It translates network, vulnerability, monitoring, and incident evidence into a practical security modernization strategy supported by enterprise architecture, risk prioritization, detection engineering, and six reproducible Python utilities.

The engagement demonstrates how technical findings can be converted into executive decisions, defensible controls, and measurable remediation priorities. All scenarios and data are synthetic; no production deployment or real financial institution is represented.

## Business Challenge

FICBANK's scenario includes exposed administrative services, weak network segmentation, incomplete security telemetry, alerting gaps, and inconsistent vulnerability governance. These conditions increase the likelihood and potential impact of unauthorized access, lateral movement, delayed detection, and unresolved risk.

The consulting objective is to reduce attack surface, strengthen access decisions, improve detection and response, and establish a repeatable path from finding discovery through validated remediation or governed risk acceptance.

## Engagement Lifecycle

1. **Network assessment:** identify reachable hosts, open ports, services, and administrative exposure.
2. **Vulnerability assessment:** analyze Nessus-style findings and prioritize remediation by severity and exposure.
3. **Security monitoring:** evaluate visibility gaps and develop Splunk detection content.
4. **Incident response:** extract indicators, organize evidence, and support repeatable investigation.
5. **Risk analysis:** combine technical severity with exploitability, exposure, and business criticality.
6. **Security modernization:** translate findings into Zero Trust, segmentation, SIEM, EDR, and governance recommendations.

## Security Modernization Strategy

The proposed target state uses layered controls to reduce both likelihood and impact:

- Place Internet-facing, internal, data, endpoint, and management resources in purpose-specific security zones.
- Require explicit identity, device posture, least-privilege policy, and enforcement decisions for protected access.
- Centralize identity, network, endpoint, and vulnerability context in Splunk Enterprise Security.
- Add endpoint detection and response for investigation, isolation, containment, and evidence preservation.
- Govern vulnerabilities through risk-based prioritization, patch approval, remediation validation, and time-limited exceptions.
- Feed investigation outcomes and validation results back into detection and risk decisions.

## Python Security Toolkit

The toolkit uses the Python standard library and safe sample inputs. Each utility documents its input contract, assumptions, output, and limitations in [scripts/README.md](scripts/README.md).

| Utility | Consulting use case | Primary output |
| --- | --- | --- |
| `log_parser.py` | Initial security-log review | Severity, authentication, source, and suspicious-event summary |
| `nmap_parser.py` | Network exposure assessment | Hosts, services, sensitive ports, and observed risk level |
| `vulnerability_summary.py` | Vulnerability prioritization | Severity trends, affected assets, exposed services, and remediation tiers |
| `risk_calculator.py` | Asset-level risk ranking | Weighted scores based on criticality, severity, exposure, exploitability, and CVSS |
| `ioc_extractor.py` | Incident triage and threat hunting | Normalized IPs, domains, URLs, emails, CVEs, and file hashes |
| `splunk_query_generator.py` | Detection engineering | Documented SPL searches with MITRE ATT&CK context and tuning notes |

## Enterprise Architecture

The [architecture](architecture/) collection documents the proposed defense-in-depth target state and its supporting workflows:

- [Enterprise security architecture](architecture/01-enterprise-security-architecture.md)
- [Zero Trust access flow](architecture/02-zero-trust-access-flow.md)
- [Network segmentation](architecture/03-network-segmentation.md)
- [Splunk monitoring architecture](architecture/04-splunk-monitoring-architecture.md)
- [Endpoint detection and response workflow](architecture/05-edr-workflow.md)
- [Vulnerability management lifecycle](architecture/06-vulnerability-management-lifecycle.md)

These are design recommendations for the fictional scenario, not claims of implemented production controls.

## Assessment Evidence

[Network Assessment Screenshot]

[Vulnerability Assessment Screenshot]

[Splunk Monitoring Screenshot]

[Incident Investigation Screenshot]

[Risk Analysis Screenshot]

[Enterprise Architecture Screenshot]

## Executive Reports

The future `reports/` collection will present decision-ready findings, business impact, prioritized recommendations, ownership, validation criteria, and residual-risk considerations for executive and technical stakeholders.

## Repository Structure

The following tree shows the desired future organization. It is a roadmap and does not claim that every planned deliverable is complete.

```text
enterprise-cybersecurity-modernization/
|-- README.md
|-- LICENSE
|-- .gitignore
|-- requirements.txt
|-- architecture/                    # Target-state designs and workflows
|-- engagement-artifacts/
|   |-- 01-network-assessment/       # Discovery and exposure evidence
|   |-- 02-vulnerability-assessment/ # Findings and remediation analysis
|   |-- 03-security-monitoring/      # SIEM and detection artifacts
|   |-- 04-incident-response/        # Investigation and IOC artifacts
|   |-- 05-risk-analysis/            # Risk register and control mapping
|   `-- 06-security-modernization/   # Roadmap and validation planning
|-- reports/                         # Executive and technical reports
|-- scripts/                         # Python utilities and detailed guide
|-- sample-data/                     # Synthetic reproducible inputs
`-- images/                          # Future sanitized portfolio evidence
```

## Quick Start

Python 3.12 or later is recommended. The current utilities require no third-party runtime packages.

```text
python scripts/log_parser.py sample-data/sample.log
python scripts/nmap_parser.py sample-data/sample_nmap.xml
python scripts/vulnerability_summary.py sample-data/sample_nessus.csv
python scripts/risk_calculator.py sample-data/sample_assets.csv sample-data/sample_findings.csv
python scripts/ioc_extractor.py sample-data/sample_incident_report.txt
python scripts/splunk_query_generator.py failed_login
```

Each file-based utility can also run with its default bundled input. Display any CLI contract with `python scripts/<utility>.py --help`.

## Skills Demonstrated

- Security assessment and attack-surface analysis
- Vulnerability prioritization and remediation governance
- Security monitoring, SPL development, and detection tuning
- Incident analysis, IOC extraction, and evidence handling
- Enterprise security, Zero Trust, and segmentation architecture
- Risk modeling and executive security communication
- Python CLI engineering, defensive parsing, and data normalization
- Translating assessment results into an actionable modernization roadmap

## Framework Alignment

| Framework or principle | Application |
| --- | --- |
| NIST SP 800-53 Rev. 5 | Aligns recommendations with access control, audit, incident response, risk assessment, configuration, and system integrity control families. |
| NIST SP 800-115 | Guides technical assessment planning, discovery, analysis, reporting, and remediation validation. |
| NIST Zero Trust | Applies resource-centric access, continuous context, least privilege, explicit policy decisions, and enforcement. |
| CISA Zero Trust Maturity Model | Frames improvement across identity, devices, networks, applications and workloads, data, visibility, analytics, automation, and orchestration. |
| MITRE ATT&CK | Connects observed behaviors and SPL detections to adversary techniques and coverage discussions. |
| Defense in Depth | Layers preventive, detective, responsive, and governance controls so no single safeguard is relied upon. |

## Future Enhancements

- Add sanitized assessment evidence to the existing placeholders.
- Publish executive and technical reports with measurable remediation outcomes.
- Add control mappings and a risk register to the engagement workstreams.
- Render architecture documents as portfolio-ready diagrams.
- Add automated regression tests for utility outputs and malformed-input handling.
- Expand Splunk detections with validation datasets and documented tuning decisions.

## Disclaimer

FICBANK is entirely fictional. All names, scenarios, findings, data, and recommendations are synthetic and intended solely to demonstrate cybersecurity consulting and engineering capabilities. Nothing in this repository represents access to, assessment of, or deployment within a real financial institution, and the material should not be treated as production security guidance without environment-specific validation.