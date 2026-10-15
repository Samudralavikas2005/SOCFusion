import csv
import sys
import json
from collections import defaultdict, Counter

def main():
    csv.field_size_limit(sys.maxsize)
    filename = 'data/processed/normalized_events_v2.csv'
    
    missing_ts_events = []
    
    with open(filename, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get('timestamp'):
                missing_ts_events.append(row)
                
    print(f"Total missing timestamps: {len(missing_ts_events)}")
    
    breakdown = defaultdict(int)
    samples = {}
    
    for row in missing_ts_events:
        src = row.get('source_file', '')
        tech = row.get('technique_id', '')
        log = row.get('log_type', '')
        ec = row.get('event_code', '')
        
        key = (src, tech, log, ec)
        breakdown[key] += 1
        
        if src not in samples:
            samples[src] = []
        if len(samples[src]) < 3:
            samples[src].append(row.get('raw_event', ''))
            
    print("\n--- BREAKDOWN ---")
    for key, count in sorted(breakdown.items(), key=lambda x: x[1], reverse=True):
        print(f"File: {key[0]} | Tech: {key[1]} | LogType: {key[2]} | EventCode: {key[3]} | Count: {count}")
        
    print("\n--- SAMPLES ---")
    for src, raw_list in samples.items():
        print(f"\nSOURCE: {src}")
        for i, raw in enumerate(raw_list):
            try:
                parsed = json.loads(raw)
                print(f"Sample {i+1} JSON keys: {list(parsed.keys())}")
                ts_candidates = {k: v for k, v in parsed.items() if 'time' in k.lower() or 'date' in k.lower()}
                print(f"Timestamp candidates: {ts_candidates}")
            except Exception as e:
                print(f"Sample {i+1} (not json): {raw[:200]}...")

if __name__ == "__main__":
    main()
