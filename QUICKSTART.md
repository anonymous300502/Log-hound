# SentinelGraph - Quick Start Guide

## 🚀 Get Running in 5 Minutes

### Step 1: Install Dependencies
```bash
cd SentinelGraph
pip install -r requirements.txt
```

### Step 2: Generate Test Data
```bash
# Create 5,000 sample events with attack scenarios
python generate_sample_data.py --events 5000 --output test_logs.csv
```

### Step 3: Run Without Neo4j (Fastest)
```bash
# Process logs and generate alerts (no graph visualization)
python main.py --csv test_logs.csv --no-graph --export-alerts alerts.json
```

**Expected Output:**
```
Starting SentinelGraph Pipeline
================================================================================
Input CSV: test_logs.csv
Mappings: config/mappings.yaml
Rules: config/rules.yaml
Graph Sync: False
================================================================================

[Stage 1/4] INGESTION - Reading raw CSV logs
--------------------------------------------------------------------------------
Processing chunk 1 (1000 records)
...

PIPELINE COMPLETE - Final Statistics
================================================================================
Raw Events Processed:    5000
Events Mapped to OCSF:   4850
Events Skipped:          150
Alerts Generated:        12
```

### Step 4: Review Alerts
```bash
# View generated alerts
cat alerts.json | python -m json.tool | less
```

**Sample Alert:**
```json
{
  "alert_id": "BF_01_1234567890",
  "rule_id": "BF_01",
  "rule_name": "Brute Force - Excessive Failed Logons from Single IP",
  "severity": "high",
  "description": "Detected 15+ failed logon attempts from same IP in 60 seconds",
  "timestamp": "2025-03-18T10:30:45.123456",
  "event_count": 20,
  "metadata": {
    "rule_type": "threshold",
    "threshold": 15,
    "actual_count": 20,
    "group_key": "10.0.0.66"
  }
}
```

---

## 🔧 Optional: Add Neo4j Graph Visualization

### Step 1: Install Neo4j
```bash
# Download from https://neo4j.com/download/
# Or use Docker:
docker run -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/password neo4j:latest
```

### Step 2: Run with Graph Sync
```bash
python main.py --csv test_logs.csv \
  --neo4j-uri bolt://localhost:7687 \
  --neo4j-user neo4j \
  --neo4j-password password
```

### Step 3: Query the Graph
Open browser to http://localhost:7474 and run:

```cypher
// View all alerts
MATCH (a:Alert) RETURN a LIMIT 25

// Find users involved in alerts
MATCH (u:User)-[:TRIGGERED]->(a:Alert)
RETURN u.name, count(a) as alert_count
ORDER BY alert_count DESC

// Blast radius from compromised user
MATCH (u:User {name: 'Administrator'})-[*1..3]-(connected)
RETURN DISTINCT connected LIMIT 50
```

---

## 📊 What You'll See

### Attack Scenarios Detected

The sample data includes realistic attack scenarios:

1. **Brute Force Attack** (Event 4625)
   - 15+ failed logons from IP 10.0.0.66
   - Triggers: `BF_01`, `BF_02`

2. **Lateral Movement** (Events 4624 → 4688)
   - Network logon followed by suspicious process
   - Triggers: `LM_01`

3. **Privilege Escalation** (Events 4720 → 4732)
   - New account created and added to Administrators
   - Triggers: `PE_01`, `PE_02`

### Example Console Output
```
ALERT: Brute Force - Excessive Failed Logons from Single IP (BF_01_1710753045123)
ALERT: Lateral Movement - Network Logon Followed by Process Execution (LM_01_1710753098456)
ALERT: Privilege Escalation - New Local Admin Account Created (PE_02_1710753210789)
```

---

## 📈 Next Steps

### 1. Process Real Logs
Export Windows Event Logs to CSV:
```powershell
# PowerShell: Export Security logs
Get-WinEvent -LogName Security | 
  Select TimeCreated, @{Name='EventXML';Expression={$_.ToXml()}} | 
  Export-Csv -Path security_logs.csv -NoTypeInformation
```

Then run:
```bash
python main.py --csv security_logs.csv
```

### 2. Customize Detection Rules
Edit `config/rules.yaml` to add your own rules:
```yaml
- id: CUSTOM_01
  name: "My Custom Detection"
  type: atomic
  class: 1007
  filter: "process.name == 'suspicious.exe'"
  severity: critical
```

### 3. Query Blast Radius
```bash
# Find all systems a user accessed
python main.py --blast-radius user Administrator

# Find all activity from suspicious IP
python main.py --blast-radius ip 192.168.1.50
```

---

## 🔍 Verify Installation

Run this test to ensure everything works:

```bash
# Test 1: Generate data
python generate_sample_data.py --events 100 --output test.csv

# Test 2: Process without graph
python main.py --csv test.csv --no-graph

# Test 3: Check logs
cat sentinelgraph.log

# Expected: "PIPELINE COMPLETE" with statistics
```

---

## ⚠️ Common Issues

### No Alerts Generated
- **Cause**: Sample data might not trigger all rules
- **Solution**: Generate more events: `--events 10000`

### Events Skipped
- **Normal**: Not all Event IDs are mapped (only 4624, 4625, 4688, 4720, 4732, 5140 in sample)
- **Solution**: Add more mappings in `config/mappings.yaml`

### Memory Error
- **Cause**: Dataset too large
- **Solution**: Reduce chunk size: `--chunk-size 100`

---

## 📚 Learn More

- **Full Documentation**: See `README.md`
- **Usage Examples**: See `USAGE_EXAMPLES.md`
- **Detection Rules**: See `config/rules.yaml`
- **OCSF Mappings**: See `config/mappings.yaml`

---

## 🎯 Success Checklist

- [x] Dependencies installed (`pip install -r requirements.txt`)
- [x] Sample data generated (`generate_sample_data.py`)
- [x] Pipeline runs successfully (`main.py --csv test_logs.csv`)
- [x] Alerts generated (check `alerts.json`)
- [x] Logs reviewed (`sentinelgraph.log`)
- [ ] Neo4j connected (optional)
- [ ] Real logs processed
- [ ] Custom rules added
- [ ] Blast radius queries executed

---

**You're Ready to Hunt Threats!** 🛡️

Start with sample data, then move to real Windows Event Logs for production threat hunting.
