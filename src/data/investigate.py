import os
import sys
import csv
import re
import hashlib
from collections import Counter, defaultdict

INPUT_FILE = "/home/vikas/SOCFusion/data/processed/normalized_events.csv"
OUTPUT_DIR = "/home/vikas/SOCFusion/data/analysis/investigation"

def is_valid_timestamp(ts):
    if not ts:
        return False
    return bool(re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', ts))

def hash_dict(d):
    return hashlib.sha256(str(sorted(d.items())).encode('utf-8')).hexdigest()

def hash_str(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    csv.field_size_limit(sys.maxsize)
    
    invalid_ts_count = 0
    total_events = 0
    invalid_ts_by_tech = Counter()
    invalid_ts_by_src = Counter()
    invalid_ts_by_log = Counter()
    invalid_ts_samples = []
    
    exact_row_hashes = Counter()
    
    raw_event_info = defaultdict(lambda: {'count': 0, 'timestamps': set(), 'techniques': set()})
    
    file_stats = defaultdict(lambda: {
        'total': 0, 'valid_ts': 0, 'invalid_ts': 0, 
        'unique_re': set(), 'unique_ts': set(), 'event_ids': set(),
        'technique_id': '', 'scenario': '', 'log_type': set()
    })

    print("Streaming dataset...")
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_events += 1
            
            ts = row.get('timestamp', '')
            tech = row.get('technique_id', '')
            src = row.get('source_file', '')
            log_type = row.get('log_type', '')
            raw = row.get('raw_event', '')
            scen = row.get('scenario', '')
            eid = row.get('event_code', '')
            
            valid_ts = is_valid_timestamp(ts)
            if not valid_ts:
                invalid_ts_count += 1
                invalid_ts_by_tech[tech] += 1
                invalid_ts_by_src[src] += 1
                invalid_ts_by_log[log_type] += 1
                if len(invalid_ts_samples) < 200:
                    invalid_ts_samples.append({
                        'technique_id': tech,
                        'scenario': scen,
                        'source_file': src,
                        'timestamp': ts,
                        'original_timestamp': row.get('original_timestamp', ''),
                        'raw_event': raw,
                        'log_type': log_type
                    })
                    
            r_hash = hash_dict(row)
            re_hash = hash_str(raw)
            exact_row_hashes[r_hash] += 1
            
            re_info = raw_event_info[re_hash]
            re_info['count'] += 1
            if len(re_info['timestamps']) < 100:
                re_info['timestamps'].add(ts)
            re_info['techniques'].add(tech)
            
            fs = file_stats[src]
            fs['total'] += 1
            if valid_ts: fs['valid_ts'] += 1
            else: fs['invalid_ts'] += 1
            fs['unique_re'].add(re_hash)
            fs['unique_ts'].add(ts)
            if eid: fs['event_ids'].add(eid)
            fs['technique_id'] = tech
            fs['scenario'] = scen
            fs['log_type'].add(log_type)
            
            if total_events % 50000 == 0:
                print(f"Processed {total_events} rows...")
                
    print("Processing complete. Generating reports...")
    
    exact_duplicates_total = sum(v - 1 for v in exact_row_hashes.values() if v > 1)
    
    same_re_diff_ts = 0
    same_re_same_ts = 0
    same_re_diff_tech = 0
    same_re_same_ts_diff_tech = 0
    
    cross_tech_samples = []
    
    for re_hash, info in raw_event_info.items():
        if info['count'] > 1:
            if len(info['timestamps']) > 1:
                same_re_diff_ts += info['count']
            if len(info['timestamps']) == 1:
                same_re_same_ts += info['count']
                
            if len(info['techniques']) > 1:
                same_re_diff_tech += info['count']
                if len(info['timestamps']) == 1:
                    same_re_same_ts_diff_tech += info['count']
                    
                cross_tech_samples.append({
                    'raw_event_hash': re_hash,
                    'count': info['count'],
                    'techniques': "|".join(sorted(info['techniques'])),
                    'timestamps_count': len(info['timestamps'])
                })
                
    print("Writing invalid_timestamp_samples.csv")
    with open(os.path.join(OUTPUT_DIR, 'invalid_timestamp_samples.csv'), 'w', newline='', encoding='utf-8') as f:
        if invalid_ts_samples:
            w = csv.DictWriter(f, fieldnames=invalid_ts_samples[0].keys())
            w.writeheader()
            w.writerows(invalid_ts_samples)
            
    print("Writing duplicate_analysis.csv")
    with open(os.path.join(OUTPUT_DIR, 'duplicate_analysis.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['metric', 'count'])
        w.writerow(['total_exact_duplicates', exact_duplicates_total])
        w.writerow(['same_raw_event_diff_ts', same_re_diff_ts])
        w.writerow(['same_raw_event_same_ts', same_re_same_ts])
        w.writerow(['same_raw_event_diff_tech', same_re_diff_tech])
        w.writerow(['same_re_same_ts_diff_tech', same_re_same_ts_diff_tech])
        
    print("Writing cross_technique_investigation.csv")
    with open(os.path.join(OUTPUT_DIR, 'cross_technique_investigation.csv'), 'w', newline='', encoding='utf-8') as f:
        if cross_tech_samples:
            w = csv.DictWriter(f, fieldnames=cross_tech_samples[0].keys())
            w.writeheader()
            w.writerows(cross_tech_samples)
            
    print("Writing source_file_quality.csv")
    with open(os.path.join(OUTPUT_DIR, 'source_file_quality.csv'), 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=['source_file', 'technique_id', 'scenario', 'log_type', 'total_events', 'valid_ts', 'invalid_ts', 'unique_re_count', 'duplicate_re_count', 'unique_ts_count', 'event_ids'])
        w.writeheader()
        for src, fs in file_stats.items():
            w.writerow({
                'source_file': src,
                'technique_id': fs['technique_id'],
                'scenario': fs['scenario'],
                'log_type': "|".join(fs['log_type']),
                'total_events': fs['total'],
                'valid_ts': fs['valid_ts'],
                'invalid_ts': fs['invalid_ts'],
                'unique_re_count': len(fs['unique_re']),
                'duplicate_re_count': fs['total'] - len(fs['unique_re']),
                'unique_ts_count': len(fs['unique_ts']),
                'event_ids': "|".join(fs['event_ids'])
            })
            
    report = f"""# Data Quality Investigation Report

## Part 1: Timestamp Parser Investigation
- **Total Invalid Timestamps:** {invalid_ts_count}
- **Percentage of all events:** {(invalid_ts_count/total_events*100) if total_events else 0:.2f}%
- Top techniques with invalid TS: {invalid_ts_by_tech.most_common(5)}
- Top log types with invalid TS: {invalid_ts_by_log.most_common(5)}

## Part 2: Duplicate Investigation
- **Total Exact Row Duplicates (all fields identical):** {exact_duplicates_total}
- **Same raw_event, Different timestamp:** {same_re_diff_ts}
- **Same raw_event, Same timestamp:** {same_re_same_ts}
- **Same raw_event, Different technique:** {same_re_diff_tech}
- **Same raw_event AND Same timestamp, Different technique:** {same_re_same_ts_diff_tech}

## Part 3 & 4: Cross-Technique Overlap & Provenance
- **Raw Event Signatures Overlapping:** {len(cross_tech_samples)}
- Provenance is explicitly driven entirely by directory structure (e.g. `T1047/atomic_red_team/...`), meaning exact identical logs placed in multiple technique folders blindly inherit the technique label of their folder.

See CSVs for full details.
"""
    with open(os.path.join(OUTPUT_DIR, 'investigation_report.md'), 'w', encoding='utf-8') as f:
        f.write(report)
        
    print("Done.")

if __name__ == "__main__":
    main()
