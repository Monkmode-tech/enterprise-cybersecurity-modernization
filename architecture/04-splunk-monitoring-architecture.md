# Splunk Monitoring Architecture

This diagram separates continuous FICBANK security-event telemetry from periodic vulnerability and asset context before both reach Splunk Enterprise Security. Event correlation produces alerts for Security Analysis and Investigation, while contextual assessment data supports prioritization without being represented as real-time activity.

```mermaid
flowchart LR
    subgraph Telemetry[Continuous Event Telemetry]
        DMZ[DMZ Events]
        INTERNAL[Internal Network Events]
        MGMT[Management Network Events]
        IAM[Identity and Access Management Events]
        EDR[EDR Management Platform<br/>Alerts and Telemetry]
    end
    subgraph Context[Periodic Vulnerability and Asset Context]
        NMAP[Nmap Discovery and Service Context]
        NESSUS[Nessus Vulnerability Findings]
    end
    subgraph Monitoring[Security Monitoring]
        EVENTS[Continuous Event Collection]
        CONTEXT[Context Update]
        SPLUNK[Splunk Enterprise Security]
        CORRELATE[Event Correlation]
        ALERT[Security Alert]
    end
    subgraph Investigation[Security Analysis and Investigation]
        REVIEW[Alert Review]
        IOC[IOC Analysis]
        EVIDENCE[Evidence Collection]
        REPORT[Incident Reporting]
    end
    DMZ --> EVENTS
    INTERNAL --> EVENTS
    MGMT --> EVENTS
    IAM --> EVENTS
    EDR --> EVENTS
    NMAP -.->|Periodic context| CONTEXT
    NESSUS -.->|Periodic context| CONTEXT
    EVENTS --> SPLUNK
    CONTEXT -.-> SPLUNK
    SPLUNK --> CORRELATE
    CORRELATE --> ALERT
    ALERT --> REVIEW
    REVIEW --> IOC
    REVIEW --> EVIDENCE
    IOC --> REPORT
    EVIDENCE --> REPORT
    REPORT -.->|Investigation feedback| CORRELATE
```

Continuous collection addresses incomplete operational visibility, while periodic Nmap and Nessus context helps analysts interpret affected assets and vulnerabilities without treating scans as live events. Correlation and the preserved investigation feedback loop reduce alerting gaps and support repeatable analysis of indicators of compromise and unauthorized activity.
