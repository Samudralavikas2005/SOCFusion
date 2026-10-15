import csv
import sys
import os
import hashlib
import json
import time

from src.data.features.temporal import extract_temporal
from src.data.features.text import extract_text_features
from src.data.features.process import extract_process_features
from src.data.features.missingness import extract_missingness
from src.data.features.schema import generate_schema

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT_FILE = "data/processed/normalized_events_v4.csv"
    if not os.path.exists(INPUT_FILE):
        INPUT_FILE = "data/processed/normalized_events_v2.csv"
        
    OUTPUT_DIR = "data/processed/features_v1/"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("Pass 1: Building categorical vocabularies...")
    vocab_sets = {
        'log_type': set(),
        'event_code': set(),
        'source': set(),
        'process_name': set()
    }
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            for k in vocab_sets:
                val = row.get(k)
                if val:
                    vocab_sets[k].add(val)
                    
    vocabs = {}
    for k, vset in vocab_sets.items():
        sorted_vals = sorted(list(vset))
        vocabs[k] = {val: idx for idx, val in enumerate(sorted_vals, start=1)}
        
    with open(os.path.join(OUTPUT_DIR, "vocab.json"), 'w') as f:
        json.dump(vocabs, f, indent=2)
        
    generate_schema(os.path.join(OUTPUT_DIR, "feature_schema.json"))
    
    print("Pass 2: Extracting features...")
    
    stats = {
        'total_events': 0,
        'nan_count': 0,
        'infinite_count': 0
    }
    
    fieldnames = [
        "event_id", "technique_id", "scenario", "source_file",
        "hour_sin", "hour_cos", "day_of_week_sin", "day_of_week_cos",
        "log_type_idx", "event_code_idx", "source_idx", "process_name_idx",
        "is_lolbin", "msg_length", "ps_token_count", "cmd_length", "cmd_entropy", "ps_b64_indicator",
        "has_process_id", "has_user", "has_command_line"
    ]
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as fin, \
         open(os.path.join(OUTPUT_DIR, "features.csv"), 'w', encoding='utf-8', newline='') as fout:
         
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            stats['total_events'] += 1
            
            raw = row.get('raw_event', '')
            ts = row.get('timestamp', '')
            id_str = raw + ts + row.get('log_type', '') + row.get('host', '') + row.get('event_code', '')
            event_id = hashlib.md5(id_str.encode('utf-8')).hexdigest()
            
            t_feats = extract_temporal(ts)
            
            c_feats = {
                'log_type_idx': vocabs['log_type'].get(row.get('log_type'), 0),
                'event_code_idx': vocabs['event_code'].get(row.get('event_code'), 0),
                'source_idx': vocabs['source'].get(row.get('source'), 0),
                'process_name_idx': vocabs['process_name'].get(row.get('process_name'), 0)
            }
            
            txt_feats = extract_text_features(row.get('raw_message', ''), row.get('command_line', ''))
            p_feats = extract_process_features(row.get('process_name', ''))
            m_feats = extract_missingness(row)
            
            out_row = {
                'event_id': event_id,
                'technique_id': row.get('technique_id', ''),
                'scenario': row.get('scenario', ''),
                'source_file': row.get('source_file', '')
            }
            out_row.update(t_feats)
            out_row.update(c_feats)
            out_row.update(txt_feats)
            out_row.update(p_feats)
            out_row.update(m_feats)
            
            writer.writerow(out_row)
            
    with open(os.path.join(OUTPUT_DIR, "feature_statistics.json"), 'w') as f:
        json.dump(stats, f, indent=2)
        
    print("Feature engineering complete.")

if __name__ == "__main__":
    main()
