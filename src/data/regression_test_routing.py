import os
import re
from src.data.parsers.windows_kv_parser import WindowsKVParser
from src.data.parsers.sysmon_parser import SysmonXMLParser
from src.data.parsers.json_parser import JSONParser

def determine_parser(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = []
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    lines.append(line)
                    if len(lines) >= 5:
                        break
            
            if any(l.startswith('<Event') or l.startswith('<?xml') or '<System>' in l for l in lines):
                return SysmonXMLParser(), "SysmonXMLParser"
                
            if any(l.startswith('{') and l.endswith('}') for l in lines):
                return JSONParser(), "JSONParser"
                
            if any(re.match(r'^(?:\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?: [AP]M)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', l) or 'LogName=' in l or 'EventCode=' in l for l in lines):
                return WindowsKVParser(), "WindowsKVParser"
                
            filename = os.path.basename(filepath).lower()
            if filename.endswith(".json"):
                return JSONParser(), "JSONParser"
            if filename.endswith(".log"):
                return WindowsKVParser(), "WindowsKVParser"
    except Exception:
        pass
    
    return None, "None"

files = [
    "data/raw/splunk_attack_data/T1105/windows-sysmon.log",
    "data/raw/splunk_attack_data/T1105/windows-security.log",
    "data/raw/splunk_attack_data/T1562.001/windows-powershell.log",
    "data/raw/splunk_attack_data/T1562.001/windows-system.log",
    "data/raw/splunk_attack_data/T1562.001/attack_data.json",
    "data/raw/splunk_attack_data/T1105/linux-sysmon_curlwget.log",
    "data/raw/splunk_attack_data/T1105/carbon_black_events.log",
    "data/raw/splunk_attack_data/T1105/winrar.log"
]

for f in files:
    if os.path.exists(f):
        parser, name = determine_parser(f)
        print(f"{os.path.basename(f)} -> {name}")
    else:
        print(f"File not found: {f}")
