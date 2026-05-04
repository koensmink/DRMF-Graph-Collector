# DRMF Graph Collector – Container


## Structuur

```text
├── Dockerfile
├── docker-compose.yml
├── main.py
├── requirements.txt
├── .env.example
└── drmf_collector
    ├── __init__.py
    ├── graph_client.py
    ├── models.py
    ├── registry.py
    ├── utils.py
    └── evaluators
        ├── __init__.py
        ├── apps.py
        ├── auth_methods.py
        ├── cross_tenant.py
        ├── entra.py
        ├── governance.py
        ├── intune.py
        └── named_locations.py
```

## Huidige evaluatorgroepen

| Bestand | Doel |
|---|---|
| `entra.py` | Conditional Access, risk, security defaults |
| `auth_methods.py` | Authentication Methods Policy |
| `apps.py` | Admin consent, app registration restrictions |
| `cross_tenant.py` | Cross-tenant access |
| `named_locations.py` | Named locations |
| `governance.py` | Access Reviews |
| `intune.py` | BitLocker / device evidence |

## Benodigde Graph application permissions

Minimale praktische set voor deze eerste collector:

```text
AccessReview.Read.All
Application.Read.All
AuditLog.Read.All
DeviceManagementConfiguration.Read.All
DeviceManagementManagedDevices.Read.All
Directory.Read.All
IdentityRiskyUser.Read.All
Policy.Read.All
RoleManagement.Read.Directory
```

## Benodigde Entra/Microsoft permissions

```text
Security Reader
Reader
Defender read access
Exchange admin read
Purview Audit/Compliance read access
```


