# Credential Flow Graph - v1.5

## 🔐 Overview

The Credential Flow Graph models **what credentials services possess to access other services**. This is critical for security analysis, lateral movement modeling, and privilege escalation scenarios.

## 🎯 Credential Levels

### Privilege Hierarchy

```python
class CredentialLevel(Enum):
    NoAccess = 0   # No access at all
    LocalUser = 1  # Regular user account, limited privileges
    Admin = 2      # Administrative access, can modify configuration
    System = 3     # System-level access, full control
    MAXIMUM = 3    # Maximum privilege level
```

### Level Characteristics

| Level | Privileges | Typical Use | Pivot Value | Risk |
|-------|-----------|-------------|-------------|------|
| **NoAccess** | None | Blocked access | None | None |
| **LocalUser** | Read/write own data | Application accounts | Low | Medium |
| **Admin** | Configure service | Operators, management tools | High | High |
| **System** | Full control | Control plane components | Very High | Critical |

## 📊 Credential Types

### Types Supported

| Type | Description | Examples | Compromise Impact |
|------|-------------|----------|-------------------|
| **password** | Username/password | Database credentials | Direct access |
| **token** | API tokens | Bearer tokens, JWT | API access |
| **access_key** | Key-based auth | S3 access keys | Storage access |
| **certificate** | X.509 certificates | TLS client certs | Mutual TLS access |
| **service_account** | K8s service accounts | Pod identity | Cluster access |
| **client_secret** | OAuth secrets | OIDC client credentials | Identity impersonation |

## 🔑 Credential Attributes

### CredentialGrant Structure

```python
@dataclass
class CredentialGrant:
    source: str              # Service that has the credential
    target: str              # Service the credential accesses
    credential_level: CredentialLevel
    credential_type: str
    is_cached: bool         # Stored in memory (volatile)
    is_shared: bool         # Multiple services use it
    can_pivot: bool         # Useful for lateral movement
```

### Attribute Significance

**`is_cached`** - Credential stored in process memory:
- ✅ Can be extracted with memory dump
- ✅ Available after service compromise
- ❌ Lost on service restart

**`is_shared`** - Multiple services share credential:
- ⚠️ Compromise one service = access to all sharing
- ⚠️ Harder to rotate (affects multiple services)
- ⚠️ Wider attack surface

**`can_pivot`** - Useful for lateral movement:
- ✅ Admin/System level credentials
- ✅ Access to critical services
- ✅ Enable privilege escalation

## 🎯 Realistic Access Patterns

### Application → Database

**Pattern**: Applications get dedicated database users
```
harbor → postgresql [LocalUser, password, cached]
keycloak → postgresql [LocalUser, password, cached]
airflow → postgresql [LocalUser, password, cached]
```

**Security Properties**:
- ✅ Principle of least privilege
- ✅ Isolated credentials per application
- ⚠️ Often cached in memory

### Monitoring → Services

**Pattern**: Monitoring uses read-only service accounts
```
prometheus → all_services [LocalUser, service_account]
grafana → prometheus [LocalUser, token]
grafana → loki [LocalUser, token]
```

**Security Properties**:
- ✅ Read-only access
- ✅ Service account (K8s managed)
- ✅ No cached passwords

### Operators → Managed Services

**Pattern**: Operators have admin access to manage resources
```
clickhouse-operator → clickhouse [Admin, password, pivot]
minio-operator → minio [Admin, access_key, pivot]
rabbitmq-cluster-operator → rabbitmq [Admin, password, pivot]
```

**Security Properties**:
- ⚠️ High privilege level
- ⚠️ Can reconfigure services
- 🚨 Prime targets for attackers

### System → Control Plane

**Pattern**: System components have elevated access
```
cilium → etcd [System, certificate, cached, pivot]
vault → etcd [Admin, certificate, pivot]
```

**Security Properties**:
- 🚨 Critical infrastructure access
- 🚨 Certificate-based (harder to rotate)
- 🚨 Maximum impact if compromised

## 📈 Credential Flow Metrics

### Generated Metrics

```json
{
  "credential_metrics": {
    "total_credentials": 45,
    "cached_credentials": 12,
    "shared_credentials": 8,
    "pivot_credentials": 6,
    "admin_or_system": 5,
    "by_level": {
      "LocalUser": 38,
      "Admin": 4,
      "System": 3
    },
    "by_type": {
      "password": 20,
      "service_account": 15,
      "token": 5,
      "access_key": 3,
      "certificate": 2
    }
  }
}
```

### Metric Interpretation

**High `cached_credentials`**: More opportunities for memory extraction attacks

**High `shared_credentials`**: Credential compromise has wider impact

**High `pivot_credentials`**: More lateral movement possibilities

**High `admin_or_system`**: Critical privilege escalation paths

## 🎮 Security Analysis Use Cases

### 1. Privilege Escalation Path Finding

```python
import json

with open('cluster.json', 'r') as f:
    data = json.load(f)

creds = data['network_topology']['credential_flow']

# Find paths to admin/system access
high_value_targets = [c for c in creds if c['credential_level'] in ['Admin', 'System']]

print("🎯 High-Value Credential Targets:")
for cred in high_value_targets:
    print(f"Compromise {cred['source']} → Gain {cred['credential_level']} access to {cred['target']}")
```

**Output**:
```
🎯 High-Value Credential Targets:
Compromise vault → Gain Admin access to postgresql
Compromise cilium → Gain System access to etcd
Compromise clickhouse-operator → Gain Admin access to clickhouse
```

### 2. Cached Credential Extraction

```python
# Find services with cached credentials (memory dump targets)
cached = [c for c in creds if c['is_cached']]

print("💾 Memory Extraction Targets:")
for cred in cached:
    impact = "HIGH" if cred['can_pivot'] else "MEDIUM"
    print(f"[{impact}] {cred['source']} - cached {cred['credential_type']} for {cred['target']}")
```

**Output**:
```
💾 Memory Extraction Targets:
[HIGH] harbor - cached password for postgresql
[MEDIUM] airflow - cached password for redis
[HIGH] jenkins - cached password for postgresql
```

### 3. Shared Credential Impact Analysis

```python
# Assess shared credential risk
shared = [c for c in creds if c['is_shared']]

# Group by target to find shared patterns
from collections import defaultdict
shared_patterns = defaultdict(list)
for cred in shared:
    shared_patterns[cred['target']].append(cred['source'])

print("🔄 Shared Credential Patterns:")
for target, sources in shared_patterns.items():
    print(f"{target} accessed by: {', '.join(sources)}")
    print(f"  → Compromise ANY of these = access to {target}")
```

### 4. Lateral Movement Graph

```python
# Build attack graph for lateral movement
def find_pivot_paths(entry_point, creds):
    """Find all services reachable via credential pivoting"""
    reachable = {entry_point}
    queue = [entry_point]
    
    while queue:
        current = queue.pop(0)
        
        # Find credentials this service has
        for cred in creds:
            if cred['source'] == current and cred['can_pivot']:
                if cred['target'] not in reachable:
                    reachable.add(cred['target'])
                    queue.append(cred['target'])
    
    return reachable

# Example: What can attacker reach from compromised Harbor?
reachable = find_pivot_paths('harbor', creds)
print(f"From 'harbor' can reach: {reachable}")
```

### 5. Critical Credential Choke Points

```python
# Find services that are credential hubs (have many credentials)
from collections import Counter

sources = Counter(c['source'] for c in creds)

print("🎯 Credential-Rich Targets (compromise = many credentials):")
for service, count in sources.most_common(10):
    pivot_count = sum(1 for c in creds if c['source'] == service and c['can_pivot'])
    print(f"  {service:30s} {count:3d} credentials ({pivot_count} pivot-capable)")
```

## 🔍 Real-World Attack Scenarios

### Scenario 1: Database Credential Theft

**Initial Access**: Compromise `harbor` via CVE

**Credential Extraction**:
```
harbor → postgresql [LocalUser, password, cached] ✓
```

**Impact**:
- Extract cached PostgreSQL password from memory
- Direct database access
- Access to `keycloak`, `mlflow`, `vault` data

### Scenario 2: Operator Compromise

**Initial Access**: Compromise `clickhouse-operator`

**Credential Exploitation**:
```
clickhouse-operator → clickhouse [Admin, password, pivot] ✓
```

**Impact**:
- Admin access to ClickHouse
- Can modify analytics data
- Can create backdoor admin users

### Scenario 3: Monitoring Infrastructure

**Initial Access**: Compromise `prometheus`

**Credential Exploitation**:
```
prometheus → [all_services] [LocalUser, service_account] ✓
```

**Impact**:
- Service account token extraction
- Read access to most services
- Wide reconnaissance capability

### Scenario 4: PKI/Secret Management

**Initial Access**: Compromise `vault`

**Credential Exploitation**:
```
vault → postgresql [Admin, password, pivot] ✓
vault → etcd [Admin, certificate, pivot] ✓
```

**Impact**:
- Admin access to core infrastructure
- Access to all secrets
- Complete cluster compromise

## 📊 Output Format

### JSON Structure

```json
{
  "credential_flow": [
    {
      "source": "harbor",
      "target": "postgresql",
      "credential_level": "LocalUser",
      "credential_type": "password",
      "is_cached": true,
      "is_shared": false,
      "can_pivot": false
    },
    {
      "source": "vault",
      "target": "postgresql",
      "credential_level": "Admin",
      "credential_type": "password",
      "is_cached": false,
      "is_shared": false,
      "can_pivot": true
    }
  ]
}
```

### NetworkX Graph Export

```python
from network_topology_generator import topology_to_networkx, GraphType
import networkx as nx

# Build credential graph
G = nx.DiGraph()

for cred in topology.credential_flow:
    G.add_edge(
        cred.source,
        cred.target,
        level=cred.credential_level.value,
        type=cred.credential_type,
        cached=cred.is_cached,
        pivot=cred.can_pivot
    )

# Find critical paths
critical_targets = ['postgresql', 'etcd', 'vault']
for target in critical_targets:
    # Find all services with credentials to this target
    sources = [s for s, t in G.edges() if t == target]
    print(f"{target}: accessible from {len(sources)} services")
```

## 🎓 Best Practices

### For Security Analysis

1. **Prioritize by privilege level**: Focus on Admin/System credentials first
2. **Map credential chains**: Track multi-hop lateral movement paths
3. **Identify credential clusters**: Find shared credential patterns
4. **Assess cache exposure**: Memory-resident credentials are high-risk
5. **Model operator compromise**: Operators are high-value targets

### For Cluster Design

1. **Minimize Admin credentials**: Use LocalUser where possible
2. **Avoid shared credentials**: Unique credentials per service
3. **Limit caching**: Use short-lived tokens instead
4. **Rotate frequently**: Especially Admin/System level
5. **Monitor credential use**: Detect anomalous access patterns

## 🔧 Integration Examples

### With CyberBattleSim

```python
def credentials_to_cyberbattle(credential_flow):
    """Convert credential flow to CyberBattleSim format"""
    
    nodes_creds = {}
    
    for cred in credential_flow:
        if cred.source not in nodes_creds:
            nodes_creds[cred.source] = {
                'credentials': [],
                'cached_credentials': []
            }
        
        cred_info = {
            'target': cred.target,
            'privilege': cred.credential_level.value,
            'type': cred.credential_type
        }
        
        if cred.is_cached:
            nodes_creds[cred.source]['cached_credentials'].append(cred_info)
        else:
            nodes_creds[cred.source]['credentials'].append(cred_info)
    
    return nodes_creds
```

### Attack Simulation

```python
class AttackSimulator:
    def __init__(self, topology):
        self.topology = topology
        self.compromised = set()
        self.stolen_creds = []
    
    def compromise_service(self, service):
        """Simulate compromising a service"""
        self.compromised.add(service)
        
        # Extract cached credentials
        for cred in self.topology.credential_flow:
            if cred.source == service and cred.is_cached:
                self.stolen_creds.append(cred)
                print(f"[+] Extracted {cred.credential_type} for {cred.target}")
    
    def use_credential(self, cred):
        """Attempt to use a stolen credential"""
        if cred.target not in self.compromised:
            self.compromised.add(cred.target)
            print(f"[+] Pivoted to {cred.target} using {cred.credential_level.name} credential")
            return True
        return False
    
    def find_path_to_target(self, target):
        """Find credential path to target service"""
        # BFS to find shortest credential path
        from collections import deque
        
        queue = deque([(s, []) for s in self.compromised])
        visited = set(self.compromised)
        
        while queue:
            current, path = queue.popleft()
            
            if current == target:
                return path
            
            for cred in self.topology.credential_flow:
                if cred.source == current and cred.target not in visited:
                    visited.add(cred.target)
                    queue.append((cred.target, path + [cred]))
        
        return None  # No path found
```

## 📚 References

- [MITRE ATT&CK - Credential Access](https://attack.mitre.org/tactics/TA0006/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
- [NIST Privilege Management](https://csrc.nist.gov/glossary/term/privilege_management)

## ✅ Summary

The Credential Flow Graph provides:

✅ **Realistic credential modeling** - Based on actual service dependencies  
✅ **Privilege levels** - NoAccess → LocalUser → Admin → System  
✅ **Attack surface analysis** - Identify high-value credential targets  
✅ **Lateral movement paths** - Map credential-based pivoting  
✅ **Memory extraction risks** - Flag cached credentials  
✅ **Shared credential impact** - Assess credential reuse risk  

**Perfect for**:
- 🎯 Red team attack planning
- 🛡️ Blue team defense modeling
- 🔬 Security research and simulation
- 📊 Privilege escalation analysis
- 🎮 CyberBattleSim integration

---

**Version:** 1.5  
**Date:** November 7, 2025  
**Credential Levels:** 4 (NoAccess, LocalUser, Admin, System)  
**Credential Types:** 6 (password, token, access_key, certificate, service_account, client_secret)
