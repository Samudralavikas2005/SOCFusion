import json
from src.data.parsers.windows_kv_parser import WindowsKVParser
from src.data.parsers.sysmon_parser import SysmonXMLParser
from src.data.parsers.json_parser import JSONParser

def test_parser():
    print("Testing Windows PowerShell 4104...")
    ps_parser = WindowsKVParser()
    events = list(ps_parser.parse("data/raw/splunk_attack_data/T1562.001/windows-powershell.log", "T1562.001", "default", "T1562.001/windows-powershell.log"))
    
    print(f"Total normalized events produced: {len(events)}")
    invalid_ts = sum(1 for e in events if not e['timestamp'])
    print(f"Invalid timestamps: {invalid_ts}")
    
    for e in events:
        if e.get('event_code') == '4104':
            print("--- Sample 4104 Event ---")
            print(f"Timestamp: {e['timestamp']}")
            print(f"Original Timestamp: {e['original_timestamp']}")
            print(f"raw_event length: {len(e['raw_event'])}")
            print("Check internal blank lines:")
            print("\\n\\n in raw_event:", "\n\n" in e['raw_event'])
            print("Contains '#requires -version 3.0':", "#requires -version 3.0" in e['raw_event'])
            break
            
    print("\nTesting Sysmon XML...")
    sysmon_parser = SysmonXMLParser()
    events_sysmon = list(sysmon_parser.parse("data/raw/splunk_attack_data/T1105/windows-sysmon.log", "T1105", "default", "T1105/windows-sysmon.log"))
    print(f"Sysmon events: {len(events_sysmon)}")
    
    print("\nTesting JSON...")
    json_parser = JSONParser()
    events_json = list(json_parser.parse("data/raw/splunk_attack_data/T1562.001/attack_data.json", "T1562.001", "default", "T1562.001/attack_data.json"))
    print(f"JSON events: {len(events_json)}")
    
if __name__ == "__main__":
    test_parser()
