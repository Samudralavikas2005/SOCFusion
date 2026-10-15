import os
import sys
import csv
import argparse
import hashlib
from collections import Counter, defaultdict
from datetime import datetime

def parse_args():
    parser = argparse.ArgumentParser(description="Profile normalized events dataset.")
    parser.add_argument("--input", required=True, help="Input CSV file path")
    parser.add_argument("--output", required=True, help="Output directory path (without trailing slash/filename for the prefix)")
    return parser.parse_args()

def main():
    csv.field_size_limit(sys.maxsize)
    args = parse_args()
    input_file = args.input
    output_dir = args.output
    
    out_dir = os.path.dirname(output_dir)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        
    out_prefix = output_dir

    total_events = 0
    columns = []
    
    technique_dist = Counter()
    scenario_dist = Counter()
    log_type_dist = Counter()
    event_id_dist = Counter()
    source_file_dist = Counter()
    
    host_dist = Counter()
    user_dist = Counter()
    
    missingness = Counter()
    
    min_timestamp = None
    max_timestamp = None
    has_subsecond_precision = False
    
    raw_event_size_min = float('inf')
    raw_event_size_max = 0
    raw_event_size_sum = 0
    
    exact_row_hashes = set()
    exact_duplicate_count = 0
    
    raw_event_techniques = defaultdict(set)
    duplicate_raw_event_count = 0
    seen_raw_events = set()
    
    overlapping_hashes = set()

    with open(input_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames
        
        for row in reader:
            total_events += 1
            
            for col in columns:
                if not row.get(col):
                    missingness[col] += 1
                    
            tech = row.get('technique_id', 'unknown')
            technique_dist[tech] += 1
            scenario_dist[row.get('scenario', 'unknown')] += 1
            log_type_dist[row.get('log_type', 'unknown')] += 1
            event_id_dist[row.get('event_code', 'unknown')] += 1
            source_file_dist[row.get('source_file', 'unknown')] += 1
            
            if row.get('host'): host_dist[row.get('host')] += 1
            if row.get('user'): user_dist[row.get('user')] += 1
            
            ts = row.get('timestamp')
            if ts:
                if min_timestamp is None or ts < min_timestamp: min_timestamp = ts
                if max_timestamp is None or ts > max_timestamp: max_timestamp = ts
                if '.' in ts:
                    has_subsecond_precision = True
                    
            raw_event = row.get('raw_event', '')
            re_len = len(raw_event)
            if re_len < raw_event_size_min: raw_event_size_min = re_len
            if re_len > raw_event_size_max: raw_event_size_max = re_len
            raw_event_size_sum += re_len
            
            row_hash = hashlib.sha256(str(sorted(row.items())).encode('utf-8')).hexdigest()
            if row_hash in exact_row_hashes:
                exact_duplicate_count += 1
            else:
                exact_row_hashes.add(row_hash)
                
            re_hash = hashlib.sha256(raw_event.encode('utf-8')).hexdigest()
            if re_hash in seen_raw_events:
                duplicate_raw_event_count += 1
            else:
                seen_raw_events.add(re_hash)
                
            raw_event_techniques[re_hash].add(tech)
            if len(raw_event_techniques[re_hash]) > 1:
                overlapping_hashes.add(re_hash)

    if raw_event_size_min == float('inf'):
        raw_event_size_min = 0

    cross_technique_overlaps = []
    for h in overlapping_hashes:
        techs = raw_event_techniques[h]
        cross_technique_overlaps.append({
            'raw_event_hash': h,
            'techniques': "|".join(sorted(list(techs))),
            'technique_count': len(techs)
        })
        
    def write_counter_csv(filename, counter, col1, col2):
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([col1, col2])
            for k, v in counter.most_common():
                writer.writerow([k, v])
                
    write_counter_csv(os.path.join(out_dir, "technique_distribution.csv"), technique_dist, "technique_id", "count")
    write_counter_csv(os.path.join(out_dir, "field_missingness.csv"), missingness, "field", "missing_count")
    write_counter_csv(os.path.join(out_dir, "event_id_distribution.csv"), event_id_dist, "event_code", "count")
    write_counter_csv(os.path.join(out_dir, "source_file_distribution.csv"), source_file_dist, "source_file", "count")
    
    with open(os.path.join(out_dir, "cross_technique_overlap.csv"), 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['raw_event_hash', 'techniques', 'technique_count'])
        writer.writeheader()
        for overlap in cross_technique_overlaps:
            writer.writerow(overlap)
            
    warnings = []
    if total_events > 0:
        if exact_duplicate_count > 0:
            warnings.append(f"High number of exact row duplicates found: {exact_duplicate_count} ({exact_duplicate_count/total_events*100:.2f}%)")
        if duplicate_raw_event_count > 0:
            warnings.append(f"High number of duplicate raw_events found: {duplicate_raw_event_count} ({duplicate_raw_event_count/total_events*100:.2f}%)")
        if len(overlapping_hashes) > 0:
            warnings.append(f"LABEL LEAKAGE/OVERLAP RISK: {len(overlapping_hashes)} raw events are labeled with MULTIPLE techniques.")
        if missingness.get('timestamp', 0) > 0:
            warnings.append(f"Found {missingness['timestamp']} events missing timestamps.")
        if not has_subsecond_precision:
            warnings.append("No sub-second precision timestamps detected across the dataset.")

    md_content = f"""# Dataset Profile: SOCFusion Normalized Events

## 1. Overview
- **Total Events:** {total_events}
- **Total Columns:** {len(columns)}
- **Columns:** {', '.join(columns)}

## 2. Timestamps
- **Earliest:** {min_timestamp}
- **Latest:** {max_timestamp}
- **Sub-second Precision Present:** {'Yes' if has_subsecond_precision else 'No'}

## 3. Data Quality Warnings
"""
    if warnings:
        for w in warnings:
            md_content += f"- {w}\n"
    else:
        md_content += "- No immediate data quality issues detected.\n"
        
    md_content += f"""
## 4. Distributions
- **Unique Techniques:** {len(technique_dist)}
- **Unique Scenarios:** {len(scenario_dist)}
- **Unique Log Types:** {len(log_type_dist)}
- **Unique Event Codes:** {len(event_id_dist)}
- **Unique Source Files:** {len(source_file_dist)}
- **Unique Hosts:** {len(host_dist)}
- **Unique Users:** {len(user_dist)}

## 5. Completeness (Missingness Highlights)
"""
    if total_events > 0:
        md_content += f"""- **Host Missing:** {missingness.get('host', 0)} ({missingness.get('host', 0)/total_events*100:.2f}%)
- **User Missing:** {missingness.get('user', 0)} ({missingness.get('user', 0)/total_events*100:.2f}%)
- **Process ID Missing:** {missingness.get('process_id', 0)} ({missingness.get('process_id', 0)/total_events*100:.2f}%)
- **Parent Process ID Missing:** {missingness.get('parent_process_id', 0)} ({missingness.get('parent_process_id', 0)/total_events*100:.2f}%)
- **Command Line Missing:** {missingness.get('command_line', 0)} ({missingness.get('command_line', 0)/total_events*100:.2f}%)
- **Source IP Missing:** {missingness.get('src_ip', 0)} ({missingness.get('src_ip', 0)/total_events*100:.2f}%)
"""

    md_content += f"""
## 6. Raw Event Statistics
- **Min Size:** {raw_event_size_min} bytes
- **Max Size:** {raw_event_size_max} bytes
- **Avg Size:** {(raw_event_size_sum/total_events if total_events > 0 else 0):.2f} bytes

## 7. Duplicate & Overlap Analysis
- **Exact Row Duplicates:** {exact_duplicate_count}
- **Duplicate Raw Events:** {duplicate_raw_event_count}
- **Cross-Technique Overlaps (Raw Events):** {len(overlapping_hashes)}
"""
    
    md_filepath = f"{out_prefix}.md" if not out_prefix.endswith('.md') else out_prefix
    with open(md_filepath, 'w', encoding='utf-8') as f:
        f.write(md_content)

if __name__ == '__main__':
    main()
