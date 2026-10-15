import re
from datetime import datetime, timezone, timedelta

gt_text = r"""
09/23/19 11:23:29 -- Manually accessed console on Sysclient0201 and navigated to news.com:8000 to download runme.bat, a malicious news.com PowerShell empire stager
09/23/19 11:26:02 -- On Sysclient0201 agent VL8B5T3U, Used PowerShell Empire Module Bypasses UAC, which performs a registry modification of the "windir" value in "Environment" to bypass UAC.
09/23/19 11:33:14 -- On Sysclient0201 agent LUAVR71T, ran Mimikatz to collect clear text passwords in memory
09/23/19 11:37:15 -- On Sysclient0201 agent LUAVR71T, used psinject to inject into the LSASS process
09/23/19 11:39:25 -- On Sysclient0201 agent LUAVR71T, established persistence by modifying HKCU:Software\Microsoft\Windows\CurrentVersion\Debug registry entry
09/23/19 11:40:41 -- On Sysclient0201 agent LUAVR71T, obtained process listing by running ps through PowerShell
09/23/19 12:51:59 -- On Sysclient0201 agent LUAVR71T, collected data collection by obtaining a screenshot of the desktop.
09/23/19 12:58:20 -- On Sysclient0201 agent LUAVR71T, conducted ARP scan on /22 of 142.20.56.202
09/23/19 13:15:48 -- On Sysclient0201 agent LUAVR71T, executed ping sweep against 142.20.56.0/24
09/23/19 13:24:36 -- On Sysclient0201 agent LUAVR71T, pivoted to Sysclient0402 using invoke_wmi
09/23/19 13:29:47 -- On Sysclient0402 agent NEK5H8GX, imported and ran ping sweep script to run against 142.20.57.0/24
09/23/19 13:35:22 -- On Sysclient0402 agent NEK5H8GX, pivoted to Sysclient0660 using invoke_wmi. Agent DS29HY41 checks in.
09/23/19 13:38:31 -- On Sysclient0660 agent DS29HY41, used ipconfig to obtain IP
09/23/19 13:40:38 -- On Sysclient0660 agent DS29HY41, used Mimikatz to obtain clear-text passwords from memory
09/23/19 13:44:23 -- On Sysclient0660 agent DS29HY41, attempted to migrate to local user process with psinject. Failed to inject.
09/23/19 13:49:00 -- On Sysclient0660 agent DS29HY41, obtained list of processes with ps
09/23/19 13:50:56 -- On Sysclient0660 agent DS29HY41, attempted to inject shellcode into process ID 4480. Injection failed.
09/23/19 13:54:11 -- On Sysclient0660 agent DS29HY41, executed script to return domain controller information.
09/23/19 13:56:48 -- On Sysclient0660 agent DS29HY41, imported and ran PowerShell script to find domain controllers
09/23/19 14:02:12 -- On Sysclient0660 agent DS29HY41, downloaded file zipfldr.dll
09/23/19 14:04:45 -- On Sysclient0660 agent DS29HY41, used invoke_wmi to pivot to domain controller 1. XH32VTK5 checks in on IP 142.20.58.149
09/23/19 14:07:21 -- On DC1 agent XH32VTK5, ran Mimikatz
09/23/19 14:09:21 -- On DC1 agent XH32VTK5, gathered user hdorka's hashes using Mimikatz' lsadump capability
09/23/19 14:45:13 -- On DC1 agent XH32VTK5, used Invoke_wmi to spread to: SYSCLIENT0104, SYSCLIENT0170, SYSCLIENT0205, SYSCLIENT0255, SYSCLIENT0321, SYSCLIENT0355, SYSCLIENT0419, SYSCLIENT0462, SYSCLIENT0503, SYSCLIENT0559, SYSCLIENT0609, SYSCLIENT0771, SYSCLIENT0874, SYSCLIENT0955
09/24/19 10:28:56 -- Sent email with malicious word document to bantonio@systemia.com rsantilli@systemia.com on Sysclient0811 from sgerard@ameblo.jp
09/24/19 10:36:51 -- On Sysclient0501, opened malicious attachment named payroll.docx. Agent K3G1U8DN checks in.
09/24/19 10:40:14 -- On Sysclient0811, opened malicious attachment named payroll.docx. Agent DS8V3RNH checks in.
09/24/19 10:46:02 -- On Sysclient0501 agent K3G1U8DN, injected PowerShell script to pivot to PowerShell Empire on  sports.com 202.6.172.98 port 443, Agent 4BW2MKUF checks in.
09/24/19 11:03:36 -- Started DeathStar to auto find and obtain access to domain controller
09/24/19 11:04:12 -- Deathstar via Sysclient0501 agent 4BW2MKUF, obtains domain SID
09/24/19 11:04:35 -- Deathstar via Sysclient0501 agent 4BW2MKUF, obtains list of 43 Domain Admins
09/24/19 11:05:39 -- Deathstar via Sysclient0501 agent 4BW2MKUF, queried to find domain controllers
09/24/19 11:09:08 -- Deathstar via Sysclient0501 agent 4BW2MKUF, started lateral movement
09/24/19 11:09:22 -- Deathstar via Sysclient0501 agent 4BW2MKUF, started domain privilege escalation
09/24/19 11:09:44 -- Deathstar via Sysclient0501 agent 4BW2MKUF, attempting to elevate using bypassuac_eventvwr
09/24/19 11:10:32 -- Deathstar via Sysclient0501 agent 4BW2MKUF, searched for GPOs containing credentials using GPP SYSVOL privilege escalation
09/24/19 11:20:19 -- On Sysclient0501 agent 4BW2MKUF, installed elevated agent on domain controller. Agent VUBW3KYE on DC1.systemia.com checks in.
09/24/19 11:23:27 -- On Sysclient0501 agent 4BW2MKUF, attempted to bypassed UAC with module privesc/bypassuac_env which modifies registry entry of windir value in environment
09/24/19 11:25:06 -- On Sysclient0501 agent 4BW2MKUF, attempted bypassuac with privesc/bypassuac_fodhelper. Failed.
09/24/19 11:26:34 -- On Sysclient0501 agent 4BW2MKUF, used invoke_wmi on localhost to obtain elevated Agent. Failed to elevated, normal agent 9HUGDCRL checked in.
09/24/19 11:31:17 -- On agent VUBW3KYE, attempted to pivot to obtain elevated agent using WMI. Got access denied for DC1.systemia.com Sysclient0501 and 0502
09/24/19 11:33:15 -- On agent VUBW3KYE, pivoted to Sysclient0501 with an elevated agent by usign administrator DC1.systemia.com credentials. Agent 6H8SZPCW checks in.
09/24/19 11:34:56 -- On Sysclient0501 agent 6H8SZPCW, set persistence using WMI subscription. Set to reach back at 10:00 every day or within 5 minutes of boot.
09/24/19 11:37:35 -- On Sysclient0501 agent 6H8SZPCW, used findtrusteddocuments to enumerate registry to determine any trusted documents and trusted locations.
09/24/19 11:39:38 -- On Sysclient0501 agent 6H8SZPCW, used winenum script with keywords "important, Secret, classified" to search files and obtain host information
09/24/19 11:41:53 -- On Sysclient0501 agent 6H8SZPCW, ran script to check for windows privilege escalation vectors.
09/24/19 11:45:13 -- On Sysclient0501 agent 6H8SZPCW, uploaded plink.exe
09/24/19 13:05:03 -- On Sysclient0501 agent 6H8SZPCW, validated upload worked with ls command
09/24/19 13:11:23 -- On Sysclient0501 agent 6H8SZPCW, started reverse SSH connection to port forward RDP port to attacker system. Lost contact with agent 6H8SZPCW.
09/24/19 13:19:38 -- On Sysclient0501, connected via RDP to host via forwarded port using sysadmin account.
09/24/19 13:26:57 -- On Sysclient0501 via RDP session, downloaded fileTransfer1000.exe (nc.exe) from news.com:8080 via chrome.
09/24/19 13:31:29 -- On Sysclient0501 via RDP session, compressed documents in C:\documents for exfiltration.
09/24/19 13:44:34 -- On Sysclient0501 via RDP session, exfiltrated export.zip to port 9999 using fileTransfer1000.exe (nc.exe) news.com
09/24/19 13:46:58 -- On Sysclient0501 via RDP session, RDPed to Sysclient0974
09/24/19 13:51:45 -- On Sysclient0974 via RDP session, browsed files in C:\documents
09/24/19 13:54:43 -- On Sysclient0974 via RDP session, RDPed to Sysclient0005
09/24/19 14:06:06 -- On Sysclient0005 via RDP session, mounted network share \\142.20.61.135\share
09/24/19 14:34:31 -- On Sysclient0005 via RDP session, added majority of share drive files to compressed folder name allgone.zip and moved to user Download folder.
09/24/19 14:37:02 -- On Sysclient0005 via RDP session, navigated to news.com:4445 and downloaded movingonup.exe (nc.exe)
09/24/19 15:04:14 -- On Sysclient0005 via RDP session, exported 3.5 gb exfil file allgona.zip
09/24/19 15:42:36 -- On DC1.systemia.com agent VUBW3KYE, used invoke_wmi to spread to Sysclient0010, Sysclient0069, Sysclient0203, Sysclient0358, Sysclient0618, Sysclient0851
09/25/19 10:29:42 -- On Sysclient0051, updated notepad++, which downloaded malicious binary "update.exe" which is a Meterpreter payload.
09/25/19 10:31:08 -- On Sysclient0051, obtained system via Meterpreter's get system module. Used named pipe impersonation in memory.
09/25/19 10:32:11 -- On Sysclient0051, used Meterpreter to get CMD shell. Ran commands to find out information about local system.
09/25/19 10:33:55 -- On Sysclient0051, used ARP scanner on 142.20.56.0/22
09/25/19 10:36:28 -- On Sysclient0051, used Meterpreter enum modules to discover all installed applications
09/25/19 10:37:52 -- On Sysclient 0051, used Meterpreter enum_domain modules to identify domain controller
09/25/19 10:38:35 -- On Sysclient 0051, used Meterpreter enum_shares to identify any shares on host
09/25/19 10:40:39 -- On Sysclient 0051, migrated from process 2712 cKfGW.exe to LSASS 568
09/25/19 10:44:56 -- On Sysclient0051, ran Mimikatz to collect clear-text passwords and hashes
09/25/19 10:48:43 -- On Sysclient0051, established persistence via Meterpreter. Script written to C:\Windows\TEMP\myHbYXTpViwX.vbx. Installed Autorun at HKLM\Software\Microsoft\Windows\CurrentVersion\Run\RTqWaEHv
09/25/19 10:53:06 -- On Sysclient0051, used timestomp to edit MAC times of created files in C:\Windows\TEMP
09/25/19 11:07:41 -- On Sysclient0051, used get_gui to add administrator "admin" to administrators and RDP group
09/25/19 11:23:31 -- On Sysclient0351, conducted update to notepadd++, which downloaded malicious update.exe binary which made connection back to attacker server
09/25/19 11:24:30 -- On Sysclient0351, migrated from process 1932 to 1256 lwabeat.
09/25/19 13:42:05 -- On Sysclient0051, RDPed to machine from attacker server.
09/25/19 14:24:03 -- Reran updated.exe on Sysclient0051
"""

lines = gt_text.strip().split('\n')
parsed = []
eastern = timezone(timedelta(hours=-4))
for line in lines:
    if not line.strip(): continue
    parts = line.split(" -- ", 1)
    if len(parts) != 2: continue
    ts_str, desc = parts
    dt = datetime.strptime(ts_str.strip(), "%m/%d/%y %H:%M:%S")
    dt = dt.replace(tzinfo=eastern)
    parsed.append({"ts": dt.timestamp(), "desc": desc.strip()})

rules = [
    ("sysclient0201", "T1566.001", "download runme.bat"),
    ("sysclient0201", "T1548.002", "Bypasses UAC"),
    ("sysclient0201", "T1003.001", "Mimikatz to collect clear text"),
    ("sysclient0201", "T1055.002", "psinject to inject"),
    ("sysclient0201", "T1547.001", "established persistence by modifying HKCU"),
    ("sysclient0201", "T1057", "process listing by running ps through PowerShell"),
    ("sysclient0201", "T1113", "screenshot of the desktop"),
    ("sysclient0201", "T1018", "ARP scan"),
    ("sysclient0201", "T1018", "ping sweep against"),
    ("sysclient0201", "T1047", "pivoted to Sysclient0402 using invoke_wmi"),
    ("sysclient0402", "T1018", "ran ping sweep script"),
    ("sysclient0402", "T1047", "pivoted to Sysclient0660 using invoke_wmi"),
    ("sysclient0660", "T1016", "ipconfig to obtain IP"),
    ("sysclient0660", "T1003.001", "used Mimikatz to obtain clear-text passwords"),
    ("sysclient0660", "T1055.002", "migrate to local user process with psinject"),
    ("sysclient0660", "T1057", "obtained list of processes with ps"),
    ("sysclient0660", "T1055.001", "inject shellcode into process ID"),
    ("sysclient0660", "T1018", "return domain controller information"),
    ("sysclient0660", "T1018", "PowerShell script to find domain controllers"),
    ("sysclient0660", "T1105", "downloaded file zipfldr.dll"),
    ("sysclient0660", "T1047", "invoke_wmi to pivot to domain controller 1"),
    ("dc1", "T1003.001", "ran Mimikatz"),
    ("dc1", "T1003.001", "gathered user hdorka's hashes using Mimikatz"),
    ("dc1", "T1047", "Invoke_wmi to spread to: SYSCLIENT0104"),
    ("sysclient0811", "T1566.001", "Sent email with malicious word document"),
    ("sysclient0501", "T1566.001", "opened malicious attachment named payroll.docx"),
    ("sysclient0811", "T1566.001", "opened malicious attachment named payroll.docx. Agent DS8V3RNH"),
    ("sysclient0501", "T1059.001", "injected PowerShell script to pivot to PowerShell Empire"),
    ("sysclient0501", "T1087.002", "DeathStar to auto find and obtain access"),
    ("sysclient0501", "T1087.002", "Deathstar via Sysclient0501 agent 4BW2MKUF, obtains domain SID"),
    ("sysclient0501", "T1087.002", "Deathstar via Sysclient0501 agent 4BW2MKUF, obtains list of 43 Domain Admins"),
    ("sysclient0501", "T1018", "Deathstar via Sysclient0501 agent 4BW2MKUF, queried to find domain controllers"),
    ("sysclient0501", "T1021", "Deathstar via Sysclient0501 agent 4BW2MKUF, started lateral movement"),
    ("sysclient0501", "T1548", "Deathstar via Sysclient0501 agent 4BW2MKUF, started domain privilege escalation"),
    ("sysclient0501", "T1548.002", "Deathstar via Sysclient0501 agent 4BW2MKUF, attempting to elevate using bypassuac_eventvwr"),
    ("sysclient0501", "T1552.006", "Deathstar via Sysclient0501 agent 4BW2MKUF, searched for GPOs containing credentials"),
    ("sysclient0501", "T1047", "installed elevated agent on domain controller. Agent VUBW3KYE on DC1"),
    ("sysclient0501", "T1548.002", "privesc/bypassuac_env which modifies registry entry of windir"),
    ("sysclient0501", "T1548.002", "attempted bypassuac with privesc/bypassuac_fodhelper"),
    ("sysclient0501", "T1047", "used invoke_wmi on localhost to obtain elevated Agent"),
    ("dc1", "T1047", "attempted to pivot to obtain elevated agent using WMI. Got access denied"),
    ("dc1", "T1047", "pivoted to Sysclient0501 with an elevated agent by usign administrator DC1.systemia.com credentials"),
    ("sysclient0501", "T1546.003", "set persistence using WMI subscription"),
    ("sysclient0501", "T1082", "used findtrusteddocuments to enumerate registry"),
    ("sysclient0501", "T1082", "used winenum script with keywords"),
    ("sysclient0501", "T1082", "ran script to check for windows privilege escalation vectors"),
    ("sysclient0501", "T1105", "uploaded plink.exe"),
    ("sysclient0501", "T1082", "validated upload worked with ls command"),
    ("sysclient0501", "T1090", "started reverse SSH connection to port forward RDP port"),
    ("sysclient0501", "T1021.001", "connected via RDP to host via forwarded port using sysadmin account"),
    ("sysclient0501", "T1105", "downloaded fileTransfer1000.exe (nc.exe)"),
    ("sysclient0501", "T1560.001", "compressed documents in C:\documents for exfiltration"),
    ("sysclient0501", "T1041", "exfiltrated export.zip to port 9999"),
    ("sysclient0501", "T1021.001", "RDPed to Sysclient0974"),
    ("sysclient0974", "T1083", "browsed files in C:\documents"),
    ("sysclient0974", "T1021.001", "RDPed to Sysclient0005"),
    ("sysclient0005", "T1021.002", "mounted network share \\142.20.61.135\share"),
    ("sysclient0005", "T1560.001", "added majority of share drive files to compressed folder"),
    ("sysclient0005", "T1105", "navigated to news.com:4445 and downloaded movingonup.exe"),
    ("sysclient0005", "T1041", "exported 3.5 gb exfil file allgona.zip"),
    ("dc1", "T1047", "On DC1.systemia.com agent VUBW3KYE, used invoke_wmi to spread"),
    ("sysclient0051", "T1105", "updated notepad++, which downloaded malicious binary"),
    ("sysclient0051", "T1134.001", "obtained system via Meterpreter's get system module"),
    ("sysclient0051", "T1082", "used Meterpreter to get CMD shell. Ran commands to find out information"),
    ("sysclient0051", "T1018", "used ARP scanner on 142.20.56.0/22"),
    ("sysclient0051", "T1082", "used Meterpreter enum modules to discover all installed applications"),
    ("sysclient0051", "T1018", "used Meterpreter enum_domain modules to identify domain controller"),
    ("sysclient0051", "T1135", "used Meterpreter enum_shares to identify any shares on host"),
    ("sysclient0051", "T1055.001", "migrated from process 2712 cKfGW.exe to LSASS 568"),
    ("sysclient0051", "T1003.001", "ran Mimikatz to collect clear-text passwords and hashes"),
    ("sysclient0051", "T1547.001", "established persistence via Meterpreter. Script written to C:\Windows\TEMP"),
    ("sysclient0051", "T1070.006", "used timestomp to edit MAC times of created files"),
    ("sysclient0051", "T1078.001", "used get_gui to add administrator"),
    ("sysclient0351", "T1105", "conducted update to notepadd++, which downloaded malicious update.exe"),
    ("sysclient0351", "T1055.001", "migrated from process 1932 to 1256 lwabeat"),
    ("sysclient0051", "T1021.001", "RDPed to machine from attacker server"),
    ("sysclient0051", "T1105", "Reran updated.exe on Sysclient0051")
]

import json
ground_truth_out = []
for i, p in enumerate(parsed):
    matched = False
    for rule in rules:
        if rule[2] in p['desc']:
            # We want to give a generous window of +60 seconds, but we can also
            # extend the window to the next event's timestamp.
            next_ts = parsed[i+1]['ts'] if i+1 < len(parsed) else p['ts'] + 3600
            if next_ts - p['ts'] > 3600:
                next_ts = p['ts'] + 3600
            
            ground_truth_out.append({
                "ts_start": p['ts'] - 60,
                "ts_end": next_ts + 60,
                "host": rule[0].lower(),
                "technique": rule[1],
                "desc": p['desc']
            })
            matched = True
            break
    if not matched:
        print(f"Warning: No rule matched for {p['desc']}")

with open('data/analysis/optc_selective/rules.json', 'w') as f:
    json.dump(ground_truth_out, f, indent=2)

print(f"Mapped {len(ground_truth_out)} events.")
