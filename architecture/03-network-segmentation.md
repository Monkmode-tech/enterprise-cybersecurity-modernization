# Network Segmentation

This diagram defines proposed FICBANK security zones and their explicitly approved one-way flows. Segmentation enforcement controls separate the Internet, DMZ, internal services, protected data, management network, and endpoint/server zones, while endpoint protection and security monitoring retain controlled visibility and response paths.

```mermaid
flowchart TB
    subgraph Internet[Internet]
        EXT[External Traffic]
    end
    EDGE[Internet Segmentation Enforcement]
    subgraph DMZ[DMZ]
        PUBLIC[Public Services]
    end
    DMZFW[DMZ Segmentation Enforcement]
    subgraph Internal[Internal Network]
        BUSINESS[Internal Services]
    end
    DATAFW[Data Segmentation Enforcement]
    subgraph Data[Protected Data]
        PROTECTED[Protected Data Services]
    end
    MGMTFW[Management Segmentation Enforcement]
    subgraph Management[Management Network]
        ADMIN[Administrative Access]
        IAM[Identity and Access Management]
        ASSESS[Nmap and Nessus]
    end
    ENDPOINTFW[Endpoint Segmentation Enforcement]
    subgraph Endpoints[Endpoint and Server Zones]
        USERS[User Endpoints]
        SERVERS[Server Endpoints]
        AGENT[Endpoint EDR Agent]
        PLATFORM[EDR Management Platform]
    end
    subgraph Monitoring[Security Monitoring]
        SPLUNK[Splunk Enterprise Security]
        REVIEW[Security Analysis and Investigation]
    end
    EXT -->|Public service traffic only| EDGE --> PUBLIC
    PUBLIC -->|Required application flow only| DMZFW --> BUSINESS
    BUSINESS -->|Required data flow only| DATAFW --> PROTECTED
    USERS -->|Verified access request| ENDPOINTFW --> IAM
    IAM -->|Authorized business flow| MGMTFW --> BUSINESS
    ADMIN -->|Verified privileged request| IAM
    IAM -->|Authorized management flow| ENDPOINTFW --> SERVERS
    ASSESS -->|Approved assessment flow| MGMTFW --> DMZFW
    DMZFW --> PUBLIC
    DMZFW --> BUSINESS
    ENDPOINTFW --> SERVERS
    USERS --> AGENT
    SERVERS --> AGENT
    AGENT -->|Endpoint telemetry| PLATFORM
    PLATFORM -->|Alerts and telemetry| SPLUNK
    REVIEW -->|Approved response| PLATFORM
    PLATFORM -->|Response action| AGENT
    PUBLIC -.->|Security events| SPLUNK
    BUSINESS -.->|Security events| SPLUNK
    PROTECTED -.->|Security events| SPLUNK
    IAM -.->|Access events| SPLUNK
    SPLUNK --> REVIEW
```

![](../images/03-network-segmentation.png)

The enforced zone boundaries replace weak segmentation with purpose-limited paths and no unrestricted bidirectional connections. They prevent direct Internet access to internal, management, data, and endpoint resources; restrict administrative and assessment traffic; and reduce exposure of SMB, RDP, SSH, and administrative interfaces while preserving monitoring and response.

Figure 3-2 below illustrates the proposed network segmentation architecture recommended for FICBANK. The design applies Zero Trust principles by separating enterprise resources into logical security zones protected through internal firewalls, least-privilege communication policies, and continuous monitoring.

![](../images/03-network-segmentation-model.png)