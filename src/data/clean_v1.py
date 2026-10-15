import csv
import sys
import hashlib
import os

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT = "data/processed/normalized_events_v4.csv"
    OUTPUT = "data/processed/cleaned_events_v1.csv"
    MANIFEST = "data/processed/cleaning_manifest_v1.csv"
    
    TARGET_HASHES = {
        '10a85172a9d176debb003243aabc8faf',
        'cb64f251b8c501741595f1e76f769e39',
        '5604af0a6d404c7742c47bd6c0f8b3d8',
        '1ac4696ee30189df839b7b89a83daf13'
    }
    
    groups = {h: [] for h in TARGET_HASHES}
    
    print("Pass 1: Collecting duplicate groups...")
    with open(INPUT, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader, start=2):
            raw = row.get('raw_event', '')
            if not raw: continue
            raw_hash = hashlib.md5(raw.encode('utf-8')).hexdigest()
            if raw_hash in TARGET_HASHES:
                groups[raw_hash].append((i, row))
                
    to_remove = set()
    manifest_entries = []
    
    print("Pass 2: Verifying groups...")
    for h, members in groups.items():
        if len(members) <= 1: continue
        
        first_idx, first_row = members[0]
        valid = True
        
        for idx, row in members[1:]:
            if (row['raw_event'] != first_row['raw_event'] or
                row['timestamp'] != first_row['timestamp'] or
                row['technique_id'] != first_row['technique_id'] or
                row['source_file'] != first_row['source_file'] or
                row['host'] != first_row['host'] or
                row['event_code'] != first_row['event_code']):
                valid = False
                break
                
        if valid:
            for idx, row in members[1:]:
                to_remove.add(idx)
                manifest_entries.append({
                    'removed_row_number': idx,
                    'retained_row_number': first_idx,
                    'raw_event_hash': h,
                    'timestamp': row['timestamp'],
                    'technique_id': row['technique_id'],
                    'source_file': row['source_file'],
                    'reason': "verified exact raw_event duplicate with identical timestamp and provenance"
                })
        else:
            print(f"Group {h} failed verification. Keeping all members.")
            
    print(f"Rows to remove: {len(to_remove)}")
    
    print("Pass 3: Writing cleaned output...")
    with open(INPUT, 'r', encoding='utf-8') as fin, open(OUTPUT, 'w', encoding='utf-8', newline='') as fout:
        reader = csv.reader(fin)
        writer = csv.writer(fout)
        
        header = next(reader)
        writer.writerow(header)
        
        for i, row in enumerate(reader, start=2):
            if i not in to_remove:
                writer.writerow(row)
                
    print("Writing manifest...")
    with open(MANIFEST, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['removed_row_number', 'retained_row_number', 'raw_event_hash', 'timestamp', 'technique_id', 'source_file', 'reason'])
        writer.writeheader()
        writer.writerows(manifest_entries)
        
    print("Done generating cleaned_events_v1.csv")

if __name__ == "__main__":
    main()
