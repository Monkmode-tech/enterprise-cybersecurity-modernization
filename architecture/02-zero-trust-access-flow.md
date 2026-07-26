# Zero Trust Access Flow

This diagram applies NIST SP 800-207 principles to proposed FICBANK access decisions. Identity and Access Management verifies identity, the Policy Decision Point evaluates request context and least-privilege policy, and the Policy Enforcement Point allows or blocks the resulting connection to a protected resource.

```mermaid
flowchart LR
    subgraph Endpoints[Endpoint Layer]
        USER[User Endpoint]
        ADMIN[Administrator Endpoint]
        AGENT[Endpoint EDR Agent]
    end
    subgraph Access[Zero Trust Access]
        IAM[Identity and Access Management<br/>Identity Verification]
        INPUTS[Decision Inputs<br/>Device Posture - User Role<br/>Requested Resource - Least-Privilege Policy]
        PDP[Policy Decision Point]
        PEP[Policy Enforcement Point]
        DENY[Deny and Record]
    end
    subgraph Resources[Protected Resources]
        DMZ[DMZ Service]
        INTERNAL[Internal Network Service]
        MGMT[Management Network Resource]
    end
    subgraph Monitoring[Security Monitoring]
        PLATFORM[EDR Management Platform]
        SPLUNK[Splunk Enterprise Security]
        REVIEW[Security Analysis and Investigation]
    end
    USER -->|Access request| IAM
    ADMIN -->|Privileged access request| IAM
    USER --> AGENT
    ADMIN --> AGENT
    IAM -->|Verified identity| PDP
    AGENT -->|Device posture| INPUTS
    INPUTS --> PDP
    PDP -->|Permit or deny| PEP
    PEP -->|Denied| DENY
    PEP -->|Approved public service| DMZ
    PEP -->|Approved business access| INTERNAL
    PEP -->|Approved privileged access| MGMT
    AGENT -->|Endpoint telemetry| PLATFORM
    PLATFORM -->|Alerts and telemetry| SPLUNK
    DENY -->|Denied access event| SPLUNK
    DMZ -->|Access event| SPLUNK
    INTERNAL -->|Access event| SPLUNK
    MGMT -->|Privileged access event| SPLUNK
    SPLUNK -->|Correlated alert| REVIEW
    REVIEW -->|Approved response| PLATFORM
    PLATFORM -->|Response action| AGENT
```

![](../images/02-zero-trust-access-flow.png)

This flow prevents network location or identity alone from granting trust and places all protected-resource access behind explicit policy enforcement. Context-aware, least-privilege decisions reduce exposed administrative access, while approved and denied events improve visibility into unauthorized activity and support investigation and endpoint response.

Figure 3-3 below demonstrates identity authentication and authorization workflow.

![](../images/02-identity-access-workflow.png)
