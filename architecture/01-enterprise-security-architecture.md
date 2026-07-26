# Enterprise Security Architecture

This diagram presents the proposed defense-in-depth target state for FICBANK, a fictional financial institution. It separates externally reachable services, internal resources, privileged administration, endpoint protection, and centralized security monitoring while applying distinct identity verification, policy decision, and policy enforcement functions.

```mermaid
flowchart LR
    subgraph Internet[Internet]
        EXT[External Users]
    end
    subgraph DMZ[DMZ]
        PUB[Public Services]
    end
    subgraph Internal[Internal Network]
        APP[Internal Services]
        DATA[Protected Data Services]
    end
    subgraph Management[Management Network]
        ADMIN[Administrative Access]
        IAM[Identity and Access Management<br/>Identity Verification]
        INPUTS[Decision Inputs<br/>Device Posture - User Role<br/>Requested Resource - Least-Privilege Policy]
        PDP[Policy Decision Point]
        PEP[Policy Enforcement Point]
        VM[Vulnerability Management<br/>Nmap and Nessus]
    end
    subgraph Endpoints[Endpoint Layer]
        USER[User Endpoints]
        SERVER[Server Endpoints]
        AGENT[Endpoint EDR Agent]
        PLATFORM[EDR Management Platform]
    end
    subgraph Monitoring[Security Monitoring]
        SPLUNK[Splunk Enterprise Security]
        SOC[Security Analysis and Investigation]
    end
    EXT -->|Restricted access| PUB
    PUB -->|Approved service flow| APP
    APP -->|Approved data flow| DATA
    USER -->|Access request| IAM
    ADMIN -->|Privileged access request| IAM
    IAM -->|Verified identity| PDP
    INPUTS --> PDP
    PDP -->|Permit or deny| PEP
    PEP -->|Authorized business access| APP
    PEP -->|Authorized administration| SERVER
    USER --> AGENT
    SERVER --> AGENT
    AGENT -->|Endpoint telemetry| PLATFORM
    PLATFORM -->|Alerts and telemetry| SPLUNK
    SOC -->|Approved response| PLATFORM
    PLATFORM -->|Response action| AGENT
    PUB -->|Security events| SPLUNK
    APP -->|Security events| SPLUNK
    DATA -->|Security events| SPLUNK
    VM -->|Vulnerability context| SPLUNK
    SPLUNK -->|Correlated alerts| SOC
```

The proposed separation limits direct exposure of SMB, RDP, SSH, and administrative interfaces. Explicit policy decisions and enforcement reduce unauthorized access and lateral movement, while endpoint telemetry, vulnerability context, and security events converge in Splunk Enterprise Security to address limited monitoring, alerting gaps, and incomplete visibility.
