#!/usr/bin/env python3
"""Generate a realistic OPLC-format telemetry corpus for testing LogHound.

Emits the four real log shapes LogHound parses (PLAN.md §7):

  E  Windows Event XML  (4624/4625/4688/4720/4732/4768)
  N  NETWORK,<proto>,<sip>,<sport>,<dip>,<dport>,<pid>,<proc>
  P  <agent_ver>,<gen_s>,... ,P,NEW_PROCESS,<pid>,<name>,<path>,<parent_folder>,<user>,<ppid>,<pproc>
  I  FILE_INTEGRITY,,<action>,<path>,<md5>

Background noise across many hosts/users, plus a handful of embedded attack
scenarios so the detection engine (config/rules.yaml) fires:

  * Brute force        -> BF_01/BF_02  (>=15 failed logons from one IP / 60s)
  * Multi-IP logon     -> AB_04        (one account, 5+ IPs / 5 min)
  * Recon tools        -> DS_03        (systeminfo/whoami/ipconfig/netstat)
  * Credential dumping -> CA_01        (mimikatz.exe)
  * Encoded PowerShell -> EX_01        (powershell -enc ...)
  * PsExec lateral     -> LM_03        (psexec in cmdline)
  * Privilege escalate -> PE_01        (member added to Domain Admins)

Usage:  python3 scripts/gen_sample_logs.py [count] [out_path]
"""
import random
import sys
from datetime import datetime, timezone

COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
OUT = sys.argv[2] if len(sys.argv) > 2 else "sample_logs_50k.log"
TENANT = "acme1"
random.seed(1337)

# Environment inventory.
HOSTS = ["DC01.corp.local", "DC02.corp.local", "FILE01.corp.local", "SQL01.corp.local"] + [
    f"WKS{i:03d}.corp.local" for i in range(1, 25)
] + [f"SRV{i:02d}.corp.local" for i in range(1, 9)]
USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi",
         "svc_backup", "svc_sql", "svc_web", "admin", "jsmith", "mjones", "klee"]
DOMAIN = "CORP"
IPS = [f"10.0.{a}.{b}" for a in range(0, 6) for b in range(1, 40)]
EXES = ["explorer.exe", "chrome.exe", "outlook.exe", "svchost.exe", "cmd.exe",
        "powershell.exe", "notepad.exe", "WmiPrvSE.exe", "teams.exe", "msedge.exe",
        "wininit.exe", "services.exe", "lsass.exe", "spoolsv.exe", "python.exe"]
LOGON_TYPES = ["2", "3", "10"]  # Interactive, Network, RemoteInteractive
FILES = [r"C:\Windows\System32\drivers\etc\hosts", r"C:\inetpub\wwwroot\web.config",
         r"C:\Program Files\App\config.ini", r"C:\Users\Public\report.docx",
         r"C:\Windows\Tasks\job.xml"]

BASE = int(datetime(2026, 7, 1, 8, 0, 0, tzinfo=timezone.utc).timestamp())  # gen_s start
SPAN = 8 * 3600  # 8-hour window


def iso(gen_s: int) -> str:
    return datetime.fromtimestamp(gen_s, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def envelope(gen_s: int, host: str, sip: str, logset: str, payload: str, agent=False) -> str:
    collector_ms = gen_s * 1000 + random.randint(0, 900)
    left = f"OPLC-{TENANT},{collector_ms},{sip}"
    if agent:  # P records carry an agent version as the first field after ` #`
        return f"{left} #3.4.8,{gen_s},{host},{sip},{logset},{payload}"
    return f"{left} #{gen_s},{host},{sip},{logset},{payload}"


def data(name: str, value: str) -> str:
    return f"<Data Name='{name}'>{value}</Data>"


def event_xml(eid: int, host: str, ts: int, fields: dict) -> str:
    ed = "".join(data(k, v) for k, v in fields.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        f"<System><EventID>{eid}</EventID>"
        f"<TimeCreated SystemTime='{iso(ts)}'/><Computer>{host}</Computer></System>"
        f"<EventData>{ed}</EventData></Event>"
    )


rows: list[tuple[int, str]] = []  # (ts_ms, line)


def add_e(eid, host, ts, sip, fields):
    rows.append((ts * 1000, envelope(ts, host, sip, "E", event_xml(eid, host, ts, fields))))


def add_logon(ts, host, user, sip, success=True, ltype=None):
    eid = 4624 if success else 4625
    ltype = ltype or random.choice(LOGON_TYPES)
    add_e(eid, host, ts, sip, {
        "TargetUserName": user, "TargetDomainName": DOMAIN,
        "IpAddress": sip, "LogonType": ltype,
    })


def add_proc_xml(ts, host, sip, name, cmdline):
    add_e(4688, host, ts, sip, {"NewProcessName": name, "CommandLine": cmdline})


def add_newproc(ts, host, sip, name, user, pid=None, ppid=None, pproc="explorer.exe"):
    pid = pid or random.randint(600, 9000)
    ppid = ppid or random.randint(400, 1200)
    path = f"C:\\Windows\\System32\\{name}"
    payload = f"NEW_PROCESS,{pid},{name},{path},C:\\Windows\\System32,{DOMAIN}\\{user},{ppid},{pproc}"
    rows.append((ts * 1000, envelope(ts, host, sip, "P", payload, agent=True)))


def add_net(ts, host, sip, dip, proc):
    payload = (f"NETWORK,{random.choice(['TCP', 'UDP'])},{sip},{random.randint(1025, 65000)},"
               f"{dip},{random.choice([80, 443, 445, 3389, 53, 8080])},{random.randint(600, 9000)},{proc}")
    rows.append((ts * 1000, envelope(ts, host, sip, "N", payload)))


def add_integrity(ts, host, sip, action, path):
    md5 = "".join(random.choice("0123456789abcdef") for _ in range(32))
    payload = f"FILE_INTEGRITY,,{action},{path},{md5}"
    rows.append((ts * 1000, envelope(ts, host, sip, "I", payload)))


def rnd_ts() -> int:
    return BASE + random.randint(0, SPAN)


# ---- background noise -------------------------------------------------------
def emit_noise():
    r = random.random()
    ts = rnd_ts()
    host = random.choice(HOSTS)
    sip = random.choice(IPS)
    if r < 0.42:
        add_logon(ts, host, random.choice(USERS), sip, success=True)
    elif r < 0.50:
        add_logon(ts, host, random.choice(USERS), sip, success=False)
    elif r < 0.70:
        add_newproc(ts, host, sip, random.choice(EXES), random.choice(USERS))
    elif r < 0.78:
        add_proc_xml(ts, host, sip, f"C:\\Windows\\System32\\{random.choice(EXES)}",
                     f"{random.choice(EXES)} --run")
    elif r < 0.94:
        add_net(ts, host, sip, random.choice(IPS), random.choice(EXES))
    else:
        add_integrity(ts, host, sip, random.choice(["MODIFIED", "CREATED", "DELETED"]),
                      random.choice(FILES))


# ---- embedded attack scenarios ---------------------------------------------
def emit_scenarios():
    # 1) Brute force: 22 failed logons from one IP against DC01 within ~60s.
    t0 = BASE + 1200
    for i in range(22):
        add_logon(t0 + i * 2, "DC01.corp.local", random.choice(USERS), "10.66.66.66",
                  success=False, ltype="3")
    # ...then one success (foothold).
    add_logon(t0 + 60, "DC01.corp.local", "svc_backup", "10.66.66.66", success=True, ltype="3")

    # 2) Multi-IP logon for one account within 5 min (AB_04).
    t1 = BASE + 4000
    for i in range(7):
        add_logon(t1 + i * 20, "SRV01.corp.local", "svc_sql", f"10.9.9.{10 + i}", success=True)

    # 3) Recon burst by one user within 60s (DS_03).
    t2 = BASE + 8000
    for name in ["systeminfo.exe", "whoami.exe", "ipconfig.exe", "netstat.exe", "whoami.exe", "systeminfo.exe"]:
        add_newproc(t2 + random.randint(0, 55), "WKS013.corp.local", "10.0.3.13", name, "attacker",
                    pproc="cmd.exe")

    # 4) Credential dumping (CA_01) on the compromised workstation.
    add_newproc(BASE + 8100, "WKS013.corp.local", "10.0.3.13", "mimikatz.exe", "attacker",
                pid=6666, ppid=4444, pproc="cmd.exe")

    # 5) Encoded PowerShell (EX_01).
    add_proc_xml(BASE + 8200, "WKS013.corp.local", "10.0.3.13",
                 "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                 "powershell -nop -w hidden -enc SQBFAFgAIABbAFMAeQBzAHQAZQBtAF0A")

    # 6) PsExec lateral movement to a server (LM_03).
    add_proc_xml(BASE + 8300, "SRV02.corp.local", "10.0.5.2",
                 "C:\\Windows\\PSEXESVC.exe", "psexec \\\\SRV02 -s -accepteula cmd.exe")

    # 7) Privilege escalation: add a user to Domain Admins (PE_01).
    add_e(4732, "DC01.corp.local", BASE + 8400, "10.0.0.1",
          {"TargetUserName": "Domain Admins", "MemberName": DOMAIN + "\\attacker"})
    add_e(4732, "DC01.corp.local", BASE + 8402, "10.0.0.1",
          {"TargetUserName": "Domain Admins", "MemberName": DOMAIN + "\\svc_backup"})


emit_scenarios()
while len(rows) < COUNT:
    emit_noise()

rows.sort(key=lambda r: r[0])  # chronological, like a real collector feed
with open(OUT, "w") as f:
    for _, line in rows[:COUNT]:
        f.write(line + "\n")

print(f"wrote {min(len(rows), COUNT)} lines to {OUT}")
