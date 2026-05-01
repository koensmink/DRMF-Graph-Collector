# SECURITY.md – DRMF Graph Collector

## 1. Scope

Dit document beschrijft de security-overwegingen voor de **DRMF Graph Collector**.

De collector:
- draait als Python-applicatie in een container;
- gebruikt Microsoft Entra ID client credentials;
- leest security/configuratie-evidence uit Microsoft Graph;
- schrijft resultaten naar een JSON-bestand in een output-volume.

Buiten scope:
- remediation/write-acties;
- interactieve gebruikersauthenticatie;
- verwerking van secrets buiten runtime environment variables;
- volledige dekking van Defender, Purview, Exchange en Azure ARM collectors.

---

## 2. Architectuur op hoofdlijnen

```text
+----------------------+        +-------------------------+
| .env / Secret Store  |        | Microsoft Entra ID      |
| TENANT_ID            |------->| OAuth2 token endpoint   |
| CLIENT_ID            |        +-------------------------+
| CLIENT_SECRET        |                    |
+----------------------+                    v
                                             |
+----------------------+        +-------------------------+
| Container runtime    |------->| Microsoft Graph API     |
| Python collector     |        | read-only endpoints     |
+----------------------+        +-------------------------+
           |
           v
+----------------------+
| /output volume       |
| drmf_output.json     |
+----------------------+
```

---

## 3. Security principles

De collector is ontworpen volgens de volgende uitgangspunten:

| Principe | Toepassing |
|---|---|
| Least privilege | Alleen read-only Graph application permissions gebruiken |
| No secrets in image | Secrets worden niet in Docker image layers opgeslagen |
| Non-root runtime | Container draait als dedicated non-root user |
| Immutable runtime | Container draait read-only met alleen `/output` schrijfbaar |
| Explicit evidence | Resultaten bevatten status, confidence, evidence en timestamp |
| Fail-safe reporting | Fouten per control worden als `error` gerapporteerd, niet stil genegeerd |
| Separation of duties | Collector verzamelt evidence, maar voert geen remediatie uit |

---

## 4. STRIDE threat model

### 4.1 Spoofing

**Dreiging**

Een aanvaller kan proberen zich voor te doen als:
- de collector;
- de app registration;
- Microsoft Graph;
- een geldige runtime met geldige environment variables.

**Impact**

Misbruik van client credentials kan leiden tot ongeautoriseerde toegang tot tenantconfiguratie en security-evidence.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Client credentials flow | Alleen app registration met expliciete application permissions |
| Geen gebruikerssessies | Geen browser login, refresh tokens of delegated user context |
| Secrets buiten image | `CLIENT_SECRET` wordt via `.env` of secret store geïnjecteerd |
| TLS naar Microsoft endpoints | Graph en token endpoint worden via HTTPS benaderd |
| Container identity beperken | Container draait zonder rootrechten en zonder extra capabilities |

**Aanbevolen aanvullende maatregelen**

- Gebruik bij voorkeur een **secret store** in plaats van platte `.env` bestanden.
- Roteer `CLIENT_SECRET` periodiek.
- Overweeg workload identity / managed identity wanneer de runtime dit ondersteunt.
- Monitor sign-ins van de app registration in Entra ID.

**Restrisico**

Wie toegang heeft tot de runtime secrets kan de collectorrechten misbruiken tot de secret wordt ingetrokken of verloopt.

---

### 4.2 Tampering

**Dreiging**

Een aanvaller kan proberen:
- de collector-code aan te passen;
- output te manipuleren;
- het Docker image te vervangen;
- evidence-bestanden achteraf te wijzigen.

**Impact**

DRMF-rapportage kan onbetrouwbaar worden, met foutieve pass/fail conclusies.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Read-only container filesystem | `read_only: true` in Docker Compose |
| Beperkt schrijfpad | Alleen `/output` is schrijfbaar via volume |
| Geen package install tijdens runtime | Dependencies worden tijdens build geïnstalleerd |
| Non-root user | Runtime user `drmf` heeft minimale rechten |
| Geen Linux capabilities | `cap_drop: ALL` |
| No new privileges | `security_opt: no-new-privileges:true` |

**Aanbevolen aanvullende maatregelen**

- Pin dependency-versies explicieter bij productiegebruik.
- Gebruik image signing, bijvoorbeeld Cosign.
- Sla output op in append-only of versioned storage.
- Voeg SHA-256 hash toe per outputbestand.
- Laat CI/CD de image bouwen en publiceren, niet handmatig op productiehosts.

**Restrisico**

Het output-volume blijft bewust schrijfbaar. Een gebruiker of proces met hosttoegang kan output achteraf aanpassen.

---

### 4.3 Repudiation

**Dreiging**

Het kan onduidelijk zijn:
- wie de collector heeft uitgevoerd;
- welke versie van de collector is gebruikt;
- welke evidence op welk moment is opgehaald;
- of een fout een echte misconfiguratie of runtimeprobleem was.

**Impact**

Auditbaarheid en herleidbaarheid van DRMF-resultaten nemen af.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Timestamp per result | Elk controlresultaat bevat `timestamp_utc` |
| Run timestamp | Output bevat `generated_at_utc` |
| Status per control | Resultaat bevat `pass`, `fail`, `partial` of `error` |
| Evidence per control | JSON bevat evidence-object per control |
| Confidence veld | Resultaat maakt onderscheid tussen harde en afgeleide controles |

**Aanbevolen aanvullende maatregelen**

- Voeg collector-versie en Git commit SHA toe aan output.
- Log container runs naar centrale logging.
- Gebruik een job scheduler met audit trail, bijvoorbeeld GitHub Actions, Kubernetes CronJob, Azure Container Apps Job of een SIEM-integratie.
- Voeg immutable opslag toe voor historische runs.

**Restrisico**

Zonder centrale logging of signed output is achteraf niet cryptografisch aantoonbaar dat de output authentiek is.

---

### 4.4 Information Disclosure

**Dreiging**

De collector verwerkt gevoelige configuratie-evidence, waaronder:
- Conditional Access policy details;
- uitgesloten gebruikers/groepen;
- app governance instellingen;
- BitLocker recovery key metadata;
- sign-in metadata.

**Impact**

Onbedoelde openbaarmaking kan inzicht geven in security controls, uitzonderingen en tenantstructuur.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Geen secrets in output | Client secret wordt niet naar JSON geschreven |
| Alleen read-only evidence | Geen mutaties of remediationgegevens |
| Output naar lokaal volume | Geen externe upload standaard |
| Minimale runtime packages | Alleen `requests` als dependency |
| Geen debugdump van tokens | Access tokens worden niet gelogd |

**Aanbevolen aanvullende maatregelen**

- Behandel `drmf_output.json` als vertrouwelijke security-evidence.
- Sla output encrypted-at-rest op.
- Beperk filesystemrechten op `./output`.
- Publiceer output niet naar algemene documentlocaties zonder dataclassificatie.
- Mask of reduceer user/group identifiers wanneer rapportage breder gedeeld wordt.

**Restrisico**

Security-evidence zelf blijft gevoelig. Zelfs zonder secrets kan de output bruikbaar zijn voor reconnaissance.

---

### 4.5 Denial of Service

**Dreiging**

De collector kan:
- Graph API throttling veroorzaken;
- falen door netwerkproblemen;
- blijven hangen op trage responses;
- grote tenants zwaar belasten door brede queries.

**Impact**

Collector-runs kunnen mislukken of onvolledig bewijs opleveren.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Timeout per request | HTTP timeout in Graph client |
| Retry op tijdelijke fouten | Retry voor `429`, `500`, `502`, `503`, `504` |
| Retry-After respecteren | `Retry-After` header wordt gebruikt als aanwezig |
| Paging support | `@odata.nextLink` wordt verwerkt |
| Control-level error handling | Fout in één control stopt niet de hele run |

**Aanbevolen aanvullende maatregelen**

- Voeg rate limiting per endpoint toe.
- Gebruik `$select` en filters waar mogelijk.
- Splits grote collectors per domein: Entra, Intune, Azure, Defender, Purview.
- Draai de collector op vaste intervallen, niet continu.
- Monitor foutpercentages en runtime duur.

**Restrisico**

Bij grote tenants kunnen brede Graph queries alsnog zwaar of traag zijn. Verdere optimalisatie per endpoint blijft nodig.

---

### 4.6 Elevation of Privilege

**Dreiging**

Een aanvaller kan proberen:
- de container te gebruiken voor host escape;
- extra privileges binnen de container te verkrijgen;
- Graph permissions te misbruiken;
- read-only evidence tooling uit te breiden naar write/remediation.

**Impact**

Bij teveel rechten kan de collector een aanvalspad worden richting tenantdata of runtime-host.

**Maatregelen**

| Maatregel | Implementatie |
|---|---|
| Non-root runtime | Dedicated user `drmf` |
| Geen Linux capabilities | `cap_drop: ALL` |
| No new privileges | `no-new-privileges:true` |
| Read-only filesystem | Container filesystem is immutable tijdens runtime |
| Geen write Graph scopes | Collector is ontworpen voor read-only permissions |
| Geen shell als runtime user | User heeft `/usr/sbin/nologin` |

**Aanbevolen aanvullende maatregelen**

- Gebruik alleen application permissions die nodig zijn voor actieve evaluators.
- Verwijder ongebruikte evaluators of splits collectors per permission boundary.
- Draai de container op een geharde host.
- Gebruik runtime scanning en image vulnerability scanning.
- Overweeg rootless Docker of Podman.

**Restrisico**

Application permissions zijn tenant-breed krachtig. Te brede Graph-rechten blijven een belangrijk risico.

---

## 5. Permission model

### 5.1 Aanbevolen minimale permission-set voor huidige collector

De praktische permission-set voor de huidige MVP is:

```text
Policy.Read.All
Directory.Read.All
AuditLog.Read.All
IdentityRiskyUser.Read.All
DeviceManagementManagedDevices.Read.All
BitlockerKey.Read.All
AccessReview.Read.All
```

Afhankelijk van actieve evaluators kunnen sommige permissions worden verwijderd.

### 5.2 Hardeningadvies

Gebruik geen “één app registration voor alles” als de collector wordt uitgebreid.

Aanbevolen splitsing:

| Collector | Scope |
|---|---|
| `drmf-entra-collector` | Conditional Access, auth methods, app governance |
| `drmf-intune-collector` | devices, compliance, BitLocker, endpoint policies |
| `drmf-azure-collector` | Azure ARM, Policy, Defender for Cloud, Sentinel |
| `drmf-defender-collector` | XDR, MDE, MDO, TVM |
| `drmf-purview-collector` | DLP, audit, retention, labels |

Voordeel:
- kleinere blast radius;
- beter permissionbeheer;
- eenvoudiger troubleshooting;
- duidelijkere audit trail.

---

## 6. Secret management

### Huidige implementatie

De container verwacht secrets via environment variables:

```env
TENANT_ID=
CLIENT_ID=
CLIENT_SECRET=
```

Dit is geschikt voor development en gecontroleerde testomgevingen.

### Productieadvies

Gebruik bij voorkeur:
- Docker secrets;
- Kubernetes secrets met externe secret provider;
- Azure Key Vault;
- GitHub Actions secrets;
- managed identity of workload identity waar mogelijk.

### Niet doen

- Geen secrets in `Dockerfile`.
- Geen secrets in image build args.
- Geen secrets committen naar Git.
- Geen `.env` opnemen in backups zonder encryptie.
- Geen output delen waarin identifiers of policy-exceptions onnodig zichtbaar zijn.

---

## 7. Container hardening

De meegeleverde `docker-compose.yml` bevat:

```yaml
read_only: true
tmpfs:
  - /tmp
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
```

Daarnaast:
- draait de applicatie als non-root user;
- is alleen `/output` schrijfbaar;
- worden dependencies tijdens build geïnstalleerd;
- worden geen secrets in image layers geplaatst.

### Aanvullend aanbevolen

- Gebruik een vulnerability scanner, bijvoorbeeld Trivy of Grype.
- Scan de base image periodiek.
- Pin base image digest voor productie.
- Gebruik image signing.
- Gebruik rootless runtime waar mogelijk.
- Beperk outbound netwerkverkeer tot Microsoft identity/Graph endpoints als de omgeving dat ondersteunt.

---

## 8. Data classification

De output van de collector moet minimaal worden behandeld als:

```text
Confidential – Security Configuration Evidence
```

Reden:
- bevat tenantconfiguratie;
- bevat control gaps;
- kan uitzonderingen en beveiligingsarchitectuur tonen;
- kan gebruikt worden voor gerichte aanvallen.

### Bewaartermijn

Aanbevolen:
- korte termijn operationeel: 30–90 dagen;
- audit/evidence: conform interne audit- en compliance-eisen;
- alleen langer bewaren wanneer nodig en versleuteld.

---

## 9. Logging en monitoring

### Huidig gedrag

De collector schrijft:
- samenvatting naar stdout;
- JSON-resultaat naar outputbestand;
- foutstatus per control indien een evaluator faalt.

### Aanbevolen uitbreiding

- Voeg structured logging toe.
- Log geen tokens of secrets.
- Stuur runtime metrics naar centrale logging.
- Bewaak:
  - aantal `error` resultaten;
  - aantal `fail` resultaten;
  - Graph throttling;
  - runtime duur;
  - ontbrekende permissions.

---

## 10. Supply chain security

### Huidige dependency footprint

De Python collector gebruikt bewust een kleine dependency-set:

```text
requests
```

### Aanbevolen maatregelen

- Gebruik dependency pinning.
- Gebruik hash-verified installs met `pip-tools` of vergelijkbaar.
- Scan dependencies in CI.
- Houd base image actueel.
- Gebruik SBOM-generatie voor productie-images.
- Vermijd onnodige SDKs als de REST-calls voldoende zijn.

---

## 11. Known limitations

| Beperking | Impact |
|---|---|
| Graph-first scope | Niet alle DRMF-controls zijn via Graph bewijsbaar |
| CA policy presence ≠ enforcement | Exclusions/report-only kunnen resultaat beïnvloeden |
| Governance-controls blijven manual | Procedures, testen en approvals vereisen externe evidence |
| Sommige Intune/Graph endpoints verschillen per tenant/licentie | Mogelijke `403`, `404` of lege datasets |
| Output is niet cryptografisch ondertekend | Integriteit is afhankelijk van opslaglaag |
| Secrets via env vars | Praktisch, maar minder sterk dan managed identity/secret store |

---

## 12. Security review checklist

Gebruik deze checklist voordat de collector productie draait.

### Identity & permissions

- [ ] App registration gebruikt alleen benodigde read-only permissions.
- [ ] Admin consent is expliciet goedgekeurd.
- [ ] Secret heeft beperkte geldigheid.
- [ ] Secretrotatie is ingericht.
- [ ] App sign-ins worden gemonitord.
- [ ] Ongebruikte permissions zijn verwijderd.

### Runtime

- [ ] Container draait non-root.
- [ ] Container filesystem is read-only.
- [ ] Alleen `/output` is schrijfbaar.
- [ ] Capabilities zijn verwijderd.
- [ ] `no-new-privileges` staat aan.
- [ ] Host is gehard en gepatcht.

### Data

- [ ] Outputdirectory heeft beperkte rechten.
- [ ] Output wordt versleuteld opgeslagen.
- [ ] Output wordt niet publiek gedeeld.
- [ ] Retentie is vastgesteld.
- [ ] Evidence wordt versioned of immutable opgeslagen.

### Operations

- [ ] Errors worden centraal gemonitord.
- [ ] Collector-run heeft audit trail.
- [ ] Dependency scanning is ingericht.
- [ ] Image scanning is ingericht.
- [ ] Wijzigingen lopen via change control.

---

## 13. Conclusie

De huidige implementatie is geschikt als veilige basis voor een read-only DRMF evidence collector, mits de app registration strikt wordt beperkt tot noodzakelijke read-only rechten.

De belangrijkste resterende risico’s zijn:
1. misbruik van client credentials;
2. te brede Graph application permissions;
3. manipulatie of ongecontroleerde verspreiding van output;
4. verkeerde conclusies door het verwarren van configuratiebewijs met effectieve handhaving.

De aanbevolen vervolgstap is het splitsen van collectors per domein en permission boundary, gecombineerd met centrale logging, secret management en immutable evidence-opslag.
