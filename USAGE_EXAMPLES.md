# SentinelGraph Configuration Examples

## Running the Pipeline

### Basic Usage
```bash
# Generate sample data (for testing)
python generate_sample_data.py --events 10000 --output test_logs.csv

# Run full pipeline with all defaults
python main.py --csv test_logs.csv

# Run without graph sync (faster, for initial testing)
python main.py --csv test_logs.csv --no-graph

# Export alerts to JSON file
python main.py --csv test_logs.csv --export-alerts alerts_output.json
```

### Custom Neo4j Configuration
```bash
# Remote Neo4j instance
python main.py --csv logs.csv \
  --neo4j-uri bolt://192.168.1.100:7687 \
  --neo4j-user myuser \
  --neo4j-password mypassword

# Custom chunk size for memory management
python main.py --csv logs.csv --chunk-size 500

# Custom configuration files
python main.py --csv logs.csv \
  --mappings custom_mappings.yaml \
  --rules custom_rules.yaml
```

### Blast Radius Queries
```bash
# Query compromised user
python main.py --blast-radius user Administrator

# Query suspicious IP
python main.py --blast-radius ip 192.168.1.50

# Query infected host
python main.py --blast-radius host WKS-001
```

---

## Neo4j Cypher Queries

### Basic Queries

```cypher
// View all users
MATCH (u:User) RETURN u LIMIT 25

// View all alerts
MATCH (a:Alert) RETURN a ORDER BY a.timestamp DESC LIMIT 25

// Count events by type
MATCH (n) RETURN labels(n) as Type, count(*) as Count

// View high severity alerts
MATCH (a:Alert) 
WHERE a.severity IN ['high', 'critical']
RETURN a.rule_name, a.timestamp, a.description
ORDER BY a.timestamp DESC
```

### Threat Hunting Queries

```cypher
// Find users who logged into multiple hosts
MATCH (u:User)-[:LOGGED_INTO]->(h:Host)
WITH u, count(DISTINCT h) as host_count
WHERE host_count > 5
RETURN u.name, host_count
ORDER BY host_count DESC

// Find suspicious processes
MATCH (p:Process)
WHERE p.name IN ['mimikatz.exe', 'psexec.exe', 'procdump.exe']
RETURN p.name, p.cmd_line

// Find users accessing admin shares
MATCH (u:User)-[r:ACCESSED_SHARE]-(ip:IP)
WHERE r.share IN ['C$', 'ADMIN$']
RETURN u.name, r.share, ip.address

// Find lateral movement patterns
MATCH path = (u:User)-[:LOGGED_INTO]->(h1:Host),
             (u)-[:LOGGED_INTO]->(h2:Host)
WHERE h1 <> h2
RETURN u.name, h1.hostname, h2.hostname
LIMIT 50
```

### Alert Investigation

```cypher
// Find all entities involved in an alert
MATCH (a:Alert {rule_id: 'LM_01'})<-[:TRIGGERED]-(entity)
RETURN entity, a.timestamp
ORDER BY a.timestamp DESC

// Trace user activity timeline
MATCH (u:User {name: 'jdoe'})-[r]->(target)
RETURN type(r) as Activity, target, r.first_seen, r.count
ORDER BY r.first_seen

// Find compromised accounts (multiple failed then success)
MATCH (u:User)-[:LOGGED_INTO]->(h:Host)
WITH u, count(*) as logon_count
WHERE logon_count > 10
RETURN u.name, logon_count
```

### Blast Radius Analysis

```cypher
// 2-hop blast radius from user
MATCH path = (u:User {name: 'Administrator'})-[*1..2]-(connected)
RETURN DISTINCT connected
LIMIT 100

// Find all systems a compromised user touched
MATCH (u:User {name: 'compromised_user'})-[:LOGGED_INTO]->(h:Host)
MATCH (h)<-[:LOGGED_INTO]-(other:User)
WHERE other <> u
RETURN DISTINCT other.name as PotentiallyCompromised

// Map attack chain
MATCH path = (ip:IP)-[:ORIGINATED_FROM]->(:User)-[:EXECUTED]->(p:Process)
WHERE ip.address = '10.0.0.66'
RETURN path
```

---

## Custom Detection Rules

### Atomic Rule Template
```yaml
- id: CUSTOM_ATOMIC
  name: "Detect Specific Behavior"
  type: atomic
  severity: medium
  class: 1007  # Process Activity
  filter: "process.name == 'suspicious.exe'"
  description: "Detected execution of suspicious.exe"
  mitre_attack: "T1059 - Command and Scripting"
```

### Threshold Rule Template
```yaml
- id: CUSTOM_THRESHOLD
  name: "Repeated Behavior Detection"
  type: threshold
  severity: high
  class: 3002  # Authentication
  filter: "status == 'Failure'"
  threshold: 10
  window: 120
  group_by: "user.name"
  description: "10+ failed logons for same user in 2 minutes"
  mitre_attack: "T1110 - Brute Force"
```

### Chain Rule Template
```yaml
- id: CUSTOM_CHAIN
  name: "Multi-Step Attack Detection"
  type: chain
  severity: critical
  step_1:
    class: 3002  # Auth
    filter: "auth_protocol == 'Network' AND status == 'Success'"
  step_2:
    class: 1007  # Process
    filter: "process.name == 'malware.exe'"
  window: 60
  match_on: "dst_endpoint.hostname"
  description: "Network logon followed by malware execution"
  mitre_attack: "T1021 - Remote Services"
```

---

## Filter Expression Syntax

### Operators
- `==` : Equal to
- `!=` : Not equal to
- `>` : Greater than
- `<` : Less than
- `>=` : Greater than or equal
- `<=` : Less than or equal
- `IN` : Value in list
- `CONTAINS` : String contains substring
- `AND` : Logical AND
- `OR` : Logical OR

### Examples
```yaml
# Simple equality
filter: "user.name == 'Administrator'"

# List membership
filter: "process.name IN ['cmd.exe', 'powershell.exe', 'wmic.exe']"

# String contains
filter: "process.cmd_line CONTAINS 'mimikatz'"

# Compound conditions
filter: "status == 'Success' AND auth_protocol == 'RemoteInteractive'"

# Numeric comparison
filter: "src_endpoint.port > 49152"
```

---

## Troubleshooting

### Issue: No events being mapped

**Solution:**
1. Check CSV format - ensure XML column exists
2. Verify Event IDs in logs match mappings.yaml
3. Check sentinelgraph.log for parsing errors

```bash
# View log file
tail -f sentinelgraph.log
```

### Issue: Neo4j connection refused

**Solution:**
1. Verify Neo4j is running: `neo4j status`
2. Check correct URI: `bolt://localhost:7687`
3. Verify credentials (default: neo4j/password)

```bash
# Start Neo4j
neo4j start

# Check if running
curl http://localhost:7474
```

### Issue: Out of memory

**Solution:**
1. Reduce chunk size
2. Disable graph sync for initial run
3. Increase system memory

```bash
# Smaller chunks
python main.py --csv logs.csv --chunk-size 100

# No graph sync
python main.py --csv logs.csv --no-graph
```

---

## Performance Tuning

### For Large Datasets (10M+ events)

1. **Disable real-time graph sync**
   ```bash
   python main.py --csv large_dataset.csv --no-graph --export-alerts alerts.json
   ```

2. **Batch processing**
   ```bash
   # Split CSV into chunks
   split -l 1000000 large_dataset.csv chunk_
   
   # Process each chunk
   for file in chunk_*; do
     python main.py --csv $file --no-graph
   done
   ```

3. **Optimize Neo4j**
   ```
   # Edit neo4j.conf
   dbms.memory.heap.initial_size=4g
   dbms.memory.heap.max_size=8g
   dbms.memory.pagecache.size=4g
   ```

---

## Integration Examples

### Export to SIEM
```python
# Export alerts to JSON for SIEM ingestion
python main.py --csv logs.csv --export-alerts alerts.json

# alerts.json can be ingested into:
# - Splunk (via HTTP Event Collector)
# - Elasticsearch (via Logstash)
# - QRadar (via syslog)
```

### Automated Hunting
```bash
#!/bin/bash
# Daily threat hunting script

DATE=$(date +%Y%m%d)
LOGDIR="/path/to/logs"
OUTPUTDIR="/path/to/output"

# Collect logs
cp ${LOGDIR}/security_${DATE}.csv ${OUTPUTDIR}/

# Run SentinelGraph
python main.py \
  --csv ${OUTPUTDIR}/security_${DATE}.csv \
  --export-alerts ${OUTPUTDIR}/alerts_${DATE}.json

# Send alerts if found
if [ -s ${OUTPUTDIR}/alerts_${DATE}.json ]; then
  mail -s "Security Alerts ${DATE}" security@company.com < ${OUTPUTDIR}/alerts_${DATE}.json
fi
```

---

## Best Practices

1. **Start Small**: Test with 1,000-10,000 events before full deployment
2. **Tune Rules**: Adjust thresholds based on your environment
3. **Regular Updates**: Review and update detection rules monthly
4. **Baseline First**: Establish normal behavior patterns
5. **Document Changes**: Track custom rules in version control
6. **Monitor Performance**: Track processing times and adjust chunk sizes
7. **Archive Graphs**: Export Neo4j graphs for long-term storage
8. **Validate Alerts**: Review false positives and adjust filters

---

## Advanced Features

### Custom OCSF Classes
Add new event mappings for additional Windows events:

```yaml
"4672":  # Special privileges assigned
  ocsf_class: 3002
  mapping:
    SubjectUserName: user.name
    PrivilegeList: privileges
```

### Multi-Step Chains
Create complex 3+ step detection chains:

```yaml
- id: ADVANCED_CHAIN
  name: "Kill Chain Detection"
  type: chain
  step_1:
    class: 3002  # Initial compromise
  step_2:
    class: 1007  # Credential dumping
  step_3:
    class: 3002  # Lateral movement
  window: 300
  match_on: "user.name"
```

---

## Resources

- **OCSF Schema**: https://schema.ocsf.io/
- **Windows Event Encyclopedia**: https://www.ultimatewindowssecurity.com/
- **MITRE ATT&CK**: https://attack.mitre.org/
- **Neo4j Documentation**: https://neo4j.com/docs/
- **Cypher Query Language**: https://neo4j.com/docs/cypher-manual/

---

**Questions?** Review the README.md or check sentinelgraph.log for detailed logging.
