import csv
import sys
import hashlib
import json

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT = "data/processed/normalized_events_v4.csv"
    TARGET_HASHES = {
        '10a85172a9d176debb003243aabc8faf',
        'cb64f251b8c501741595f1e76f769e39',
        '5604af0a6d404c7742c47bd6c0f8b3d8',
        '1ac4696ee30189df839b7b89a83daf13'
    }
    
    groups = {h: [] for h in TARGET_HASHES}
    with open(INPUT, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):
            raw = row.get('raw_event', '')
            if not raw: continue
            raw_hash = hashlib.md5(raw.encode('utf-8')).hexdigest()
            if raw_hash in TARGET_HASHES:
                groups[raw_hash].append((i, row))
                
    for h, members in groups.items():
        print(f"Group {h} has {len(members)} members")
        first_idx, first_row = members[0]
        for idx, row in members[1:]:
            diffs = []
            for k in ['raw_event', 'timestamp', 'technique_id', 'source_file', 'host', 'event_code']:
                if row[k] != first_row[k]:
                    diffs.append(f"{k}: '{first_row[k]}' vs '{row[k]}'")
            print(f"  diffs for row {idx}: {diffs}")

if __name__ == "__main__":
    main()
