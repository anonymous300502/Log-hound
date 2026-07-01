"""
Sample Windows Event Log Generator
Generates synthetic event logs for testing SentinelGraph
"""

import csv
from datetime import datetime, timedelta
import random

def generate_event_4624(username, source_ip, logon_type, timestamp):
    """Generate successful logon event (4624)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4624</EventID>
    <Computer>DC01.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>{username}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='LogonType'>{logon_type}</Data>
    <Data Name='IpAddress'>{source_ip}</Data>
    <Data Name='WorkstationName'>WKS-{random.randint(1,100):03d}</Data>
    <Data Name='LogonProcessName'>Kerberos</Data>
    <Data Name='AuthenticationPackageName'>Kerberos</Data>
  </EventData>
</Event>"""

def generate_event_4625(username, source_ip, logon_type, timestamp):
    """Generate failed logon event (4625)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4625</EventID>
    <Computer>DC01.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='TargetUserName'>{username}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='LogonType'>{logon_type}</Data>
    <Data Name='IpAddress'>{source_ip}</Data>
    <Data Name='WorkstationName'>WKS-{random.randint(1,100):03d}</Data>
    <Data Name='FailureReason'>Bad password</Data>
    <Data Name='Status'>0xC000006D</Data>
  </EventData>
</Event>"""

def generate_event_4688(username, process_name, cmd_line, timestamp):
    """Generate process creation event (4688)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4688</EventID>
    <Computer>WKS-{random.randint(1,100):03d}.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>{username}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='NewProcessName'>{process_name}</Data>
    <Data Name='CommandLine'>{cmd_line}</Data>
    <Data Name='NewProcessId'>{random.randint(1000,9999)}</Data>
    <Data Name='ParentProcessName'>C:\\Windows\\explorer.exe</Data>
    <Data Name='CreatorProcessId'>{random.randint(1000,9999)}</Data>
  </EventData>
</Event>"""

def generate_event_4720(actor_user, target_user, timestamp):
    """Generate user account created event (4720)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4720</EventID>
    <Computer>DC01.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>{actor_user}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='TargetUserName'>{target_user}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
    <Data Name='SamAccountName'>{target_user}</Data>
    <Data Name='DisplayName'>{target_user}</Data>
  </EventData>
</Event>"""

def generate_event_4732(actor_user, member_user, group_name, timestamp):
    """Generate member added to group event (4732)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>4732</EventID>
    <Computer>DC01.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>{actor_user}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='MemberName'>{member_user}</Data>
    <Data Name='TargetUserName'>{group_name}</Data>
    <Data Name='TargetDomainName'>CORP</Data>
  </EventData>
</Event>"""

def generate_event_5140(username, source_ip, share_name, timestamp):
    """Generate network share access event (5140)"""
    return f"""<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
  <System>
    <EventID>5140</EventID>
    <Computer>FS01.corp.local</Computer>
    <TimeCreated SystemTime='{timestamp.isoformat()}Z'/>
  </System>
  <EventData>
    <Data Name='SubjectUserName'>{username}</Data>
    <Data Name='SubjectDomainName'>CORP</Data>
    <Data Name='IpAddress'>{source_ip}</Data>
    <Data Name='ShareName'>{share_name}</Data>
    <Data Name='ShareLocalPath'>C:\\Shares\\{share_name}</Data>
  </EventData>
</Event>"""

def generate_sample_data(output_file='sample_logs.csv', num_events=5000):
    """Generate sample event log dataset"""
    
    users = ['Administrator', 'jdoe', 'asmith', 'bmiller', 'svc_sql', 'kthompson']
    ips = [f'192.168.1.{i}' for i in range(10, 250)]
    processes = [
        ('C:\\Windows\\System32\\cmd.exe', 'cmd.exe /c whoami'),
        ('C:\\Windows\\System32\\powershell.exe', 'powershell.exe -enc SGVsbG9Xb3JsZA=='),
        ('C:\\Windows\\System32\\notepad.exe', 'notepad.exe'),
        ('C:\\Program Files\\Chrome\\chrome.exe', 'chrome.exe'),
        ('C:\\Windows\\System32\\psexec.exe', 'psexec.exe \\\\target -u admin'),
        ('C:\\Windows\\System32\\net.exe', 'net user /domain'),
    ]
    shares = ['C$', 'ADMIN$', 'IPC$', 'Public', 'Finance', 'HR']
    
    events = []
    start_time = datetime.utcnow() - timedelta(days=7)
    
    print(f"Generating {num_events} sample events...")
    
    # Generate normal activity (70%)
    for i in range(int(num_events * 0.7)):
        event_type = random.choice(['4624', '4688', '5140'])
        timestamp = start_time + timedelta(seconds=random.randint(0, 604800))
        
        if event_type == '4624':
            event_xml = generate_event_4624(
                random.choice(users),
                random.choice(ips),
                random.choice(['2', '3', '10']),
                timestamp
            )
        elif event_type == '4688':
            process = random.choice(processes)
            event_xml = generate_event_4688(
                random.choice(users),
                process[0],
                process[1],
                timestamp
            )
        else:  # 5140
            event_xml = generate_event_5140(
                random.choice(users),
                random.choice(ips),
                random.choice(shares),
                timestamp
            )
        
        events.append(event_xml)
    
    # Generate brute force attack scenario (15%)
    print("Adding brute force attack scenario...")
    attacker_ip = '10.0.0.66'
    attack_start = start_time + timedelta(days=3, hours=2)
    for i in range(int(num_events * 0.15)):
        timestamp = attack_start + timedelta(seconds=i)
        event_xml = generate_event_4625('Administrator', attacker_ip, '3', timestamp)
        events.append(event_xml)
    
    # Add successful logon after brute force
    events.append(generate_event_4624('Administrator', attacker_ip, '3', 
                                     attack_start + timedelta(seconds=120)))
    
    # Generate lateral movement scenario (10%)
    print("Adding lateral movement scenario...")
    lateral_start = start_time + timedelta(days=4, hours=14)
    lateral_user = 'bmiller'
    lateral_ip = '192.168.1.50'
    
    # Network logon
    events.append(generate_event_4624(lateral_user, lateral_ip, '3', lateral_start))
    
    # Followed by suspicious process execution
    for i in range(int(num_events * 0.1)):
        timestamp = lateral_start + timedelta(seconds=i+5)
        event_xml = generate_event_4688(
            lateral_user,
            'C:\\Windows\\System32\\cmd.exe',
            'cmd.exe /c net user /domain',
            timestamp
        )
        events.append(event_xml)
    
    # Generate privilege escalation scenario (5%)
    print("Adding privilege escalation scenario...")
    privesc_start = start_time + timedelta(days=5, hours=10)
    new_user = 'backdoor_admin'
    
    # Create user
    events.append(generate_event_4720('Administrator', new_user, privesc_start))
    
    # Add to Administrators group
    events.append(generate_event_4732('Administrator', new_user, 'Administrators',
                                     privesc_start + timedelta(seconds=5)))
    
    # Shuffle events to make it realistic
    random.shuffle(events)
    
    # Write to CSV
    print(f"Writing events to {output_file}...")
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(['EventXML'])
        for event in events:
            writer.writerow([event])
    
    print(f"✓ Generated {len(events)} events successfully!")
    print(f"\nScenarios included:")
    print(f"  - Normal activity: ~{int(num_events * 0.7)} events")
    print(f"  - Brute force attack: ~{int(num_events * 0.15)} events")
    print(f"  - Lateral movement: ~{int(num_events * 0.1)} events")
    print(f"  - Privilege escalation: ~{int(num_events * 0.05)} events")
    print(f"\nRun: python main.py --csv {output_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate sample Windows event logs')
    parser.add_argument('--output', type=str, default='sample_logs.csv',
                       help='Output CSV file (default: sample_logs.csv)')
    parser.add_argument('--events', type=int, default=5000,
                       help='Number of events to generate (default: 5000)')
    
    args = parser.parse_args()
    
    generate_sample_data(args.output, args.events)
