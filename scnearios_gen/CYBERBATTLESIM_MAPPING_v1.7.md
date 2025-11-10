# CyberBattleSim CVE Mapping - v1.7

## 🎯 Overview

The system now automatically maps real CVE vulnerabilities to **CyberBattleSim vulnerability types** based on CVSS vectors and descriptions. This enables seamless integration with CyberBattleSim for realistic attack simulation.

## 🔄 Automatic Mapping

### Vulnerability Type (LOCAL vs REMOTE)

Determined from **CVSS Attack Vector (AV)**:

| CVSS Vector | CyberBattleSim Type | Description |
|-------------|---------------------|-------------|
| AV:N (Network) | **REMOTE** | Exploitable remotely over network |
| AV:A (Adjacent) | **REMOTE** | Requires adjacent network access |
| AV:L (Local) | **LOCAL** | Requires local system access |
| AV:P (Physical) | **LOCAL** | Requires physical access |

**Example**:
```
CVE-2024-10041: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
                       ^^^^
                    Network → REMOTE
```

### Outcome Type Mapping

Maps to CyberBattleSim outcome types based on CVSS vector + description analysis:

#### 1. LeakedCredentials
**Triggered by**:
- Description keywords: "credential", "password", "authentication bypass"
- CVSS: Any vector with auth bypass indicators

**Examples**:
- CVE-2024-31081: "Redis authentication bypass" → **LeakedCredentials**
- CVE-2023-XXXX: "Password disclosure" → **LeakedCredentials**

#### 2. LeakedNodesId
**Triggered by**:
- Description: "information disclosure", "information leak", "expose"
- CVSS: C:H (High Confidentiality impact) without sensitive data keywords

**Examples**:
- CVE-2023-39191: "PostgreSQL information disclosure" → **LeakedNodesId**
- Network discovery vulnerabilities → **LeakedNodesId**

#### 3. CustomerData
**Triggered by**:
- Description: "customer data", "sensitive data", "personal information"
- CVSS: C:H (High Confidentiality) + sensitive data keywords

**Examples**:
- CVE-2023-45853: "Redis denial of service" (with data implications) → **CustomerData**
- Data breach vulnerabilities → **CustomerData**

#### 4. PrivilegeEscalation
**Triggered by**:
- Description: "privilege escalation" (general)
- CVSS: PR:L + I:H or A:H (Low privilege to high impact)
- Severity: MEDIUM

**Examples**:
- CVE-2024-10041: "PostgreSQL privilege escalation" → **PrivilegeEscalation**

#### 5. AdminEscalation
**Triggered by**:
- Description: "admin", "administrator" privilege escalation
- CVSS: PR:L + I:H + Severity HIGH

**Examples**:
- "Escalation to admin privileges" → **AdminEscalation**

#### 6. SystemEscalation
**Triggered by**:
- Description: "root", "system", "kernel" privilege escalation
- CVSS: PR:L + I:H + A:H + Severity CRITICAL
- Highest privilege level

**Examples**:
- "Kernel privilege escalation to root" → **SystemEscalation**

#### 7. LateralMove
**Triggered by**:
- Description: "remote code execution", "RCE", "arbitrary code"
- CVSS: I:H + A:H (High Integrity AND High Availability)

**Examples**:
- RCE vulnerabilities → **LateralMove**

#### 8. ExploitFailed
**Triggered by**:
- Failed exploitation attempts
- Used during simulation, not from CVE data

### Privilege Level Inference

Maps outcome type and severity to privilege levels:

| Outcome Type | Severity | Privilege Level | CyberBattleSim Enum |
|--------------|----------|-----------------|---------------------|
| SystemEscalation | CRITICAL/HIGH | **3** | System |
| AdminEscalation | HIGH | **2** | Admin |
| PrivilegeEscalation | MEDIUM/HIGH | **1-2** | LocalUser/Admin |
| LeakedCredentials | Any | **1-3** | Based on severity |
| LateralMove | CRITICAL | **3** | System |
| LateralMove | HIGH | **2** | Admin |
| LateralMove | MEDIUM | **1** | LocalUser |
| CustomerData | Any | **1** | LocalUser |
| LeakedNodesId | Any | **1** | LocalUser |

## 📊 Output Format

### Enhanced Vulnerability Object

```json
{
  "cve_id": "CVE-2024-10041",
  "severity": "HIGH",
  "cvss_score": 8.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
  "exploitability": 0.95,
  "description": "PostgreSQL privilege escalation vulnerability",
  
  "vulnerability_type": "REMOTE",
  "outcome_type": "PrivilegeEscalation",
  "privilege_level": 2
}
```

## 🎮 CyberBattleSim Integration

### Direct Mapping

```python
from vulnerability_assigner import VulnerabilityAssigner

# Load vulnerabilities
assigner = VulnerabilityAssigner("final.json", "vulnerability_db.yml")
vulns = assigner.assign_vulnerabilities("postgresql")

# Convert to CyberBattleSim format
for vuln in vulns:
    cyberbattle_vuln = {
        'id': vuln.cve_id,
        'type': vuln.vulnerability_type,  # LOCAL or REMOTE
        'outcome': vuln.outcome_type,      # LeakedCredentials, etc.
        'privilege_level': vuln.privilege_level,  # 0-3
        'exploitability': vuln.exploitability,
        'cost': 100 - int(vuln.exploitability * 100)
    }
```

### Vulnerability Library Generation

```python
def generate_cyberbattle_vulnerability_library(topology):
    """Generate CyberBattleSim VulnerabilityLibrary"""
    
    vulnerability_library = {}
    
    for service_name, service in topology['services'].items():
        for vuln in service['vulnerabilities']:
            vuln_id = vuln['cve_id']
            
            # Map outcome type to CyberBattleSim outcome class
            outcome = create_outcome(vuln['outcome_type'], vuln['privilege_level'])
            
            vulnerability_library[vuln_id] = {
                'description': vuln['description'],
                'type': vuln['vulnerability_type'],  # VulnerabilityType.LOCAL or .REMOTE
                'outcome': outcome,
                'rates': {
                    'success': vuln['exploitability'],
                    'failure': 1.0 - vuln['exploitability']
                },
                'cost': calculate_cost(vuln),
                'URL': f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
            }
    
    return vulnerability_library


def create_outcome(outcome_type, privilege_level):
    """Create appropriate CyberBattleSim outcome object"""
    
    if outcome_type == "SystemEscalation":
        return SystemEscalation()
    elif outcome_type == "AdminEscalation":
        return AdminEscalation()
    elif outcome_type == "PrivilegeEscalation":
        if privilege_level == 3:
            return SystemEscalation()
        elif privilege_level == 2:
            return AdminEscalation()
        else:
            return PrivilegeEscalation(PrivilegeLevel.LocalUser)
    elif outcome_type == "LeakedCredentials":
        # Would need to determine specific credentials
        return LeakedCredentials([...])
    elif outcome_type == "LeakedNodesId":
        return LeakedNodesId([...])
    elif outcome_type == "CustomerData":
        return CustomerData()
    elif outcome_type == "LateralMove":
        return LateralMove(success=True)
    else:
        return ExploitFailed()
```

## 📈 Statistics Example

```bash
python k8s_cluster_generator.py \
  --nodes 50 \
  --use-case microservices \
  --cve-json final.json \
  --vuln-db vulnerability_db.yml \
  --generate-topology \
  -o cluster.json
```

**Output Statistics**:
```
📡 Vulnerability Type Distribution:
  REMOTE       42
  LOCAL         8

🎯 Outcome Type Distribution:
  PrivilegeEscalation          15
  LeakedCredentials            12
  AdminEscalation               8
  LeakedNodesId                 7
  LateralMove                   5
  SystemEscalation              3
  CustomerData                  2
```

## 🔍 Analysis Examples

### 1. Find Remote Privilege Escalation Paths

```python
# Find REMOTE vulnerabilities that escalate privileges
remote_privesc = []

for service_name, service in topology['services'].items():
    for vuln in service['vulnerabilities']:
        if (vuln['vulnerability_type'] == 'REMOTE' and 
            vuln['outcome_type'] in ['PrivilegeEscalation', 'AdminEscalation', 'SystemEscalation']):
            
            remote_privesc.append({
                'service': service_name,
                'cve': vuln['cve_id'],
                'outcome': vuln['outcome_type'],
                'privilege': vuln['privilege_level'],
                'exploitability': vuln['exploitability']
            })

print("🎯 Remote Privilege Escalation Opportunities:")
for item in sorted(remote_privesc, key=lambda x: x['privilege'], reverse=True):
    print(f"  {item['service']:20s} {item['cve']:18s} → {item['outcome']:20s} (Lvl {item['privilege']})")
```

### 2. Credential Theft Opportunities

```python
# Find all credential leak vulnerabilities
cred_leaks = []

for service_name, service in topology['services'].items():
    if service['is_public']:  # Only public services
        for vuln in service['vulnerabilities']:
            if vuln['outcome_type'] == 'LeakedCredentials':
                cred_leaks.append({
                    'service': service_name,
                    'cve': vuln['cve_id'],
                    'exploitability': vuln['exploitability']
                })

print("🔑 Public Credential Leak Vulnerabilities:")
for item in sorted(cred_leaks, key=lambda x: x['exploitability'], reverse=True):
    print(f"  {item['service']:20s} {item['cve']:18s} Exploit: {item['exploitability']:.2f}")
```

### 3. Build Attack Graph

```python
# Build attack graph with CyberBattleSim vulnerability types
attack_graph = {
    'entry_points': [],
    'lateral_moves': [],
    'privilege_escalations': [],
    'data_exfiltration': []
}

# Entry points (public REMOTE vulnerabilities)
for service_name, service in topology['services'].items():
    if service['is_public']:
        remote_vulns = [v for v in service['vulnerabilities'] 
                       if v['vulnerability_type'] == 'REMOTE']
        if remote_vulns:
            attack_graph['entry_points'].append({
                'service': service_name,
                'vulnerabilities': remote_vulns
            })

# Lateral movement (RCE and LateralMove outcomes)
for service_name, service in topology['services'].items():
    lateral_vulns = [v for v in service['vulnerabilities']
                    if v['outcome_type'] == 'LateralMove']
    if lateral_vulns:
        attack_graph['lateral_moves'].append({
            'service': service_name,
            'vulnerabilities': lateral_vulns
        })

# Data exfiltration
for service_name, service in topology['services'].items():
    data_vulns = [v for v in service['vulnerabilities']
                 if v['outcome_type'] == 'CustomerData']
    if data_vulns:
        attack_graph['data_exfiltration'].append({
            'service': service_name,
            'vulnerabilities': data_vulns
        })
```

## 🎯 Mapping Decision Trees

### CVSS Vector → Vulnerability Type
```
if AV:L or AV:P:
    return LOCAL
else:
    return REMOTE
```

### Description + CVSS → Outcome Type
```
if "credential" or "password" in description:
    return LeakedCredentials
    
elif "information disclosure" in description:
    if "customer" or "sensitive" in description:
        return CustomerData
    else:
        return LeakedNodesId
        
elif "remote code execution" in description:
    return LateralMove
    
elif "privilege escalation" in description:
    if "system" or "root" in description:
        return SystemEscalation
    elif "admin" in description:
        return AdminEscalation
    else:
        return PrivilegeEscalation
        
else based on CVSS + severity:
    if C:H:
        return CustomerData
    elif I:H and A:H:
        return LateralMove
    elif PR:L and I:H:
        if severity == CRITICAL:
            return SystemEscalation
        elif severity == HIGH:
            return AdminEscalation
        else:
            return PrivilegeEscalation
```

## ✅ Summary

The CyberBattleSim mapping provides:

✅ **Automatic Type Inference** - LOCAL/REMOTE from CVSS vectors  
✅ **Outcome Classification** - 8 CyberBattleSim outcome types  
✅ **Privilege Level Mapping** - 0-3 (NoAccess → System)  
✅ **Exploitability Scoring** - Ready for simulation  
✅ **Direct Integration** - Drop-in replacement for CyberBattleSim  

**Perfect for**:
- 🎮 CyberBattleSim scenarios
- 🎯 Attack simulation
- 🔬 Exploit path analysis
- 📊 Privilege escalation modeling
- 🛡️ Defense-in-depth testing

---

**Version:** 1.7  
**Date:** November 7, 2025  
**Vulnerability Types:** LOCAL, REMOTE  
**Outcome Types:** 8 (LeakedCredentials, LeakedNodesId, PrivilegeEscalation, AdminEscalation, SystemEscalation, CustomerData, LateralMove, ExploitFailed)  
**Privilege Levels:** 0-3 (NoAccess, LocalUser, Admin, System)
