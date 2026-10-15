import sys
import csv
import re
from collections import defaultdict, Counter

def main():
    csv.field_size_limit(sys.maxsize)
    filename = 'data/processed/normalized_events_v4.csv'
    
    header_count = 0
    logical_record_count = 0
    wrong_column_count = 0
    empty_raw_event_count = 0
    missing_ts_count = 0
    newline_in_raw_event_count = 0
    provenance_missing_count = 0
    
    min_ts = None
    max_ts = None
    subsecond_count = 0
    
    source_stats = defaultdict(lambda: {'events': 0})
    tech_stats = Counter()
    
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
            
            if not raw: empty_raw_event_count += 1
            if '\n' in raw: newline_in_raw_event_count += 1
            if not tech or not scen or not src: provenance_missing_count += 1
            
            if not ts:
                missing_ts_count += 1
            else:
                if min_ts is None or ts < min_ts: min_ts = ts
                if max_ts is None or ts > max_ts: max_ts = ts
                if re.search(r'\.\d+Z$', ts):
                    subsecond_count += 1
            
            source_stats[src]['events'] += 1
            tech_stats[tech] += 1
            
    print("--- V4 VALIDATION ---")
    print(f"Header column count: {header_count}")
    print(f"Logical record count: {logical_record_count}")
    print(f"Rows with incorrect column counts: {wrong_column_count}")
    print(f"Rows with empty raw_event: {empty_raw_event_count}")
    print(f"Rows missing timestamp: {missing_ts_count}")
    print(f"Records with embedded newlines in raw_event: {newline_in_raw_event_count}")
    print(f"Events missing provenance: {provenance_missing_count}")
    print(f"Earliest timestamp: {min_ts}")
    print(f"Latest timestamp: {max_ts}")
    print(f"Events with sub-second precision: {subsecond_count}")

if __name__ == "__main__":
    main()
