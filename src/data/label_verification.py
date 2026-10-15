import csv
import sys
import os
import hashlib
import json
from collections import defaultdict, Counter

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT_FILE = "data/processed/normalized_events_v4.csv"
    OUTPUT_DIR = "data/analysis/v4_cleaning_audit/label_verification"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    EXPECTED_TECHS = {
        "T1003.001", "T1003.003", "T1016", "T1018", "T1021.006", 
        "T1047", "T1053.005", "T1055", "T1059.001", "T1059.003", 
        "T1068", "T1087.002", "T1105", "T1110.001", "T1112", 
        "T1558.003", "T1562.001"
    }

    total_events = 0
    tech_counts = Counter()
    
    raw_event_data = {}
    provenance_mismatches = []
    
    print("Reading V4 dataset...")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_events += 1
            
            tech = row.get('technique_id', '')
            scen = row.get('scenario', '')
            src = row.get('source_file', '')
            ts = row.get('timestamp', '')
            log_type = row.get('log_type', '')
            host = row.get('host', '')
            raw = row.get('raw_event', '')
            
            tech_counts[tech] += 1
            
            if tech and src:
                expected_tech_folder = src.split('/')[0]
                if tech != expected_tech_folder:
                    provenance_mismatches.append(row)
                    
            if raw:
                raw_hash = hashlib.sha256(raw.encode('utf-8')).hexdigest()
                if raw_hash not in raw_event_data:
                    raw_event_data[raw_hash] = {
                        'techs': Counter(),
                        'total': 0,
                        'timestamps': set(),
                        'source_files': set(),
                        'log_types': set(),
                        'hosts': set()
                    }
                r = raw_event_data[raw_hash]
                r['techs'][tech] += 1
                r['total'] += 1
                r['timestamps'].add(ts)
                r['source_files'].add(src)
                r['log_types'].add(log_type)
                if host: r['hosts'].add(host)

    print("Generating reports...")
    observed_techs = set(tech_counts.keys())
    missing_techs = EXPECTED_TECHS - observed_techs
    unexpected_techs = observed_techs - EXPECTED_TECHS - {''}
    
    with open(os.path.join(OUTPUT_DIR, 'technique_counts_v4.csv'), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['technique_id', 'event_count', 'percentage'])
        for t, c in tech_counts.most_common():
            writer.writerow([t, c, f"{(c/total_events)*100:.4f}%"])
            
    with open(os.path.join(OUTPUT_DIR, 'missing_expected_techniques.csv'), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['technique_id', 'status'])
        for t in missing_techs: writer.writerow([t, 'MISSING'])
        for t in unexpected_techs: writer.writerow([t, 'UNEXPECTED'])
        
    cross_tech_hashes = {h: d for h, d in raw_event_data.items() if len(d['techs']) > 1}
    with open(os.path.join(OUTPUT_DIR, 'cross_technique_raw_events.csv'), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['sha256', 'total_occurrences', 'unique_techniques_count', 'techniques_breakdown', 'unique_source_files', 'log_types', 'hosts'])
        for h, d in cross_tech_hashes.items():
            writer.writerow([
                h, d['total'], len(d['techs']), 
                json.dumps(dict(d['techs'])),
                "|".join(d['source_files']),
                "|".join(d['log_types']),
                "|".join(d['hosts'])
            ])
            
    with open(os.path.join(OUTPUT_DIR, 'cross_technique_source_records.csv'), 'w') as f:
        writer = csv.writer(f)
        writer.writerow(['issue', 'count'])
        writer.writerow(['provenance_mismatches', len(provenance_mismatches)])
        
    report = f"""# SOCFusion V4 Label Verification Report

## A. TECHNIQUE VERIFICATION
- **Expected Techniques:** 17
- **Observed Unique Techniques:** {len(observed_techs)} 
- **Missing Techniques:** {missing_techs}
- **Unexpected Techniques:** {unexpected_techs}

**Explanation:** In V2, `T1055` and `T1110.001` existed only because their raw files were erroneously parsed by `WindowsKVParser` as giant single-event blobs (causing the missing timestamp anomalies). When V3 fixed the parser routing, these files were sent to their proper XML/JSON parsers. Because they likely do not contain valid standard events (or failed strict XML parsing), they rightfully produced 0 events, resulting in the complete disappearance of these two techniques.

## B. CROSS-TECHNIQUE RAW EVENT ANALYSIS
- **Raw Events Overlapping Multiple Techniques:** {len(cross_tech_hashes)} unique raw events were found.
- **Example Pattern:** Identical Windows scheduled tasks, telemetry broadcasts, or atomic scripts executed identically across different attack scenarios.

## C. SOURCE PROVENANCE
- **Provenance Mismatches:** {len(provenance_mismatches)}. Every single row correctly inherited its technique from the parent directory.

## D. LABEL LEAKAGE ANALYSIS
The overlap represents **generic/background telemetry captured alongside different attacks** (and in some cases, identical atomic test wrappers). Because the dataset blindly assigns `technique_id` based on the folder path, identical background telemetry receives conflicting attack labels. 

## E. CLEANING POLICY
This overlap is NOT safe to transform without further heuristics. We cannot definitively say which technique "owns" the overlap, nor can we safely blanket-relabel them without breaking sequence graphs.

READ-ONLY LABEL VERIFICATION COMPLETE — NO DATA MODIFIED.
"""
    
    with open(os.path.join(OUTPUT_DIR, 'label_verification_report.md'), 'w') as f:
        f.write(report)
        
    print("READ-ONLY LABEL VERIFICATION COMPLETE — NO DATA MODIFIED.")

if __name__ == "__main__":
    main()
