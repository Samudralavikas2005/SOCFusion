import sys
import csv
import os
from collections import defaultdict, Counter

def main():
    csv.field_size_limit(sys.maxsize)
    filename = 'data/processed/normalized_events_v2.csv'
    
    header_count = 0
    logical_record_count = 0
    wrong_column_count = 0
    empty_raw_event_count = 0
    missing_ts_count = 0
    newline_in_raw_event_count = 0
    
    missing_ts_records = []
    
    source_stats = defaultdict(lambda: {
        'events': 0, 'with_ts': 0, 'without_ts': 0,
        'tech_id': set(), 'log_types': Counter(),
        'min_ts': None, 'max_ts': None
    })
    
    samples = {
        'sysmon': None,
        'Security': None,
        'System': None,
        'Microsoft-Windows-PowerShell/Operational': None,
        'json': None
    }
    
    provenance_missing_count = 0
    
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
            header_count = len(header)
        except StopIteration:
            print("Empty file")
            return
            
        f.seek(0)
        dict_reader = csv.DictReader(f)
        
        for i, row in enumerate(dict_reader, start=2): 
            logical_record_count += 1
            
            if len(row) != header_count:
                wrong_column_count += 1
                
            raw = row.get('raw_event', '')
            ts = row.get('timestamp', '')
            tech = row.get('technique_id', '')
            scen = row.get('scenario', '')
            src = row.get('source_file', '')
            log = row.get('log_type', '')
            
            if not raw:
                empty_raw_event_count += 1
            if '\n' in raw:
                newline_in_raw_event_count += 1
                
            if not ts:
                missing_ts_count += 1
                if len(missing_ts_records) < 50:
                    missing_ts_records.append({
                        'record_no': i,
                        'technique_id': tech,
                        'scenario': scen,
                        'source_file': src,
                        'log_type': log,
                        'event_code': row.get('event_code', ''),
                        'raw_len': len(raw),
                        'raw_head': raw[:200].replace('\n', '\\n')
                    })
            
            if not tech or not scen or not src:
                provenance_missing_count += 1
                
            s = source_stats[src]
            s['events'] += 1
            if ts: 
                s['with_ts'] += 1
                if s['min_ts'] is None or ts < s['min_ts']: s['min_ts'] = ts
                if s['max_ts'] is None or ts > s['max_ts']: s['max_ts'] = ts
            else: 
                s['without_ts'] += 1
            s['tech_id'].add(tech)
            s['log_types'][log] += 1
            
            if samples['Security'] is None and log == 'Security': samples['Security'] = row
            if samples['System'] is None and log == 'System': samples['System'] = row
            if samples['sysmon'] is None and log == 'sysmon': samples['sysmon'] = row
            if samples['Microsoft-Windows-PowerShell/Operational'] is None and log == 'Microsoft-Windows-PowerShell/Operational': samples['Microsoft-Windows-PowerShell/Operational'] = row
            if samples['json'] is None and src.endswith('.json'): samples['json'] = row

    print("--- 1. CSV LOGICAL RECORD VALIDATION ---")
    print(f"Header column count: {header_count}")
    print(f"Logical record count: {logical_record_count}")
    print(f"Rows with incorrect column counts: {wrong_column_count}")
    print(f"Rows with empty raw_event: {empty_raw_event_count}")
    print(f"Rows missing timestamp: {missing_ts_count}")
    print(f"Records with embedded newlines in raw_event: {newline_in_raw_event_count}")
    print()
    
    print("--- 2. INVESTIGATE THE '40 MISSING TIMESTAMP' EVENTS ---")
    for r in missing_ts_records[:5]:
        print(r)
    print()
    
    print("--- 3. VERIFY MULTILINE CSV ROUND-TRIP ---")
    for k, v in samples.items():
        if v:
            print(f"{k} sample: has {len(v.get('raw_event', ''))} bytes raw_event, \\n in raw_event: {'\\n' in v.get('raw_event', '')}")
    print()
    
    print("--- 4. SOURCE-FILE ACCOUNTING (Top 5 by events) ---")
    sorted_src = sorted(source_stats.items(), key=lambda x: x[1]['events'], reverse=True)
    for src, s in sorted_src[:5]:
        print(f"File: {src} | Events: {s['events']} | Techs: {list(s['tech_id'])} | LogTypes: {dict(s['log_types'])}")
    print()
    
    print("--- 7. PROVENANCE AUDIT ---")
    print(f"Events missing provenance (tech/scen/src): {provenance_missing_count}")

if __name__ == "__main__":
    main()
