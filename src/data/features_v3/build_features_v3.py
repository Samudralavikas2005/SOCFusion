import csv
import sys
import os
import math
import json
import re
from collections import Counter
import numpy as np

def entropy(s):
    if not s: return 0.0
    counts = Counter(s)
    ent = 0.0
    for c, freq in counts.items():
        p = freq / len(s)
        ent -= p * math.log2(p)
    return ent

def main():
    csv.field_size_limit(sys.maxsize)
    IN_CSV = "data/processed/normalized_events_v4.csv"
    HOST_PART = "data/analysis/split_v2/host_partition.csv"
    OUT_DIR = "data/processed/features_v3"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    # 1. Load Partitions
    host_to_part = {}
    with open(HOST_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_to_part[row['host']] = row['partition']
            
    # LOLBins
    lolbins = {"certutil", "bitsadmin", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "wmic", "powershell", "cmd", "pwsh"}
    
    # 2. First Pass: Get Vocabularies and Training Stats
    print("Pass 1: Computing vocabularies and normalization statistics from Train partition...")
    event_code_counts = Counter()
    log_type_counts = Counter()
    source_counts = Counter()
    
    train_lengths = {'msg': [], 'cmd': []}
    
    with open(IN_CSV, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row.get('host', '').strip()
            if not host: host = 'UNKNOWN_HOST'
            part = host_to_part.get(host)
            
            if part == 'train':
                ec = str(row.get('event_code', '')).strip()
                lt = str(row.get('log_type', '')).strip()
                src = str(row.get('source', '')).strip()
                
                if ec: event_code_counts[ec] += 1
                if lt: log_type_counts[lt] += 1
                if src: source_counts[src] += 1
                
                train_lengths['msg'].append(float(len(str(row.get('raw_message', '')))))
                train_lengths['cmd'].append(float(len(str(row.get('command_line', '')))))
                
    # Select Top N for Categoricals
    def get_top(counts, N):
        return [k for k, v in counts.most_common(N)]
        
    top_event_codes = get_top(event_code_counts, 50)
    top_log_types = get_top(log_type_counts, 20)
    top_sources = get_top(source_counts, 30)
    
    means = {
        'msg': np.mean(train_lengths['msg']),
        'cmd': np.mean(train_lengths['cmd'])
    }
    stds = {
        'msg': np.std(train_lengths['msg']) + 1e-6,
        'cmd': np.std(train_lengths['cmd']) + 1e-6
    }
    
    # 3. Second Pass: Build Features
    print("Pass 2: Building features...")
    
    # Base fields to preserve
    base_fields = ['event_id', 'timestamp', 'host', 'user', 'process_id', 'process_name', 
                   'process_path', 'command_line', 'event_code', 'log_type', 'source', 
                   'technique_id', 'scenario', 'source_file']
                   
    feature_fields = [
        'msg_len_norm', 'cmd_len_norm', 'cmd_entropy',
        'is_lolbin', 'is_powershell', 'is_cmd', 'is_encoded_b64',
        'has_network_flags', 'has_recon_flags', 'has_registry_flags',
        'has_suspicious_paths', 'has_execution_flags', 'has_admin_shares'
    ]
    
    ohe_fields = []
    for i in range(len(top_event_codes) + 1): ohe_fields.append(f'ec_{i}')
    for i in range(len(top_log_types) + 1): ohe_fields.append(f'lt_{i}')
    for i in range(len(top_sources) + 1): ohe_fields.append(f'src_{i}')
    
    out_headers = base_fields + feature_fields + ohe_fields
    
    with open(IN_CSV, 'r') as f_in, open(os.path.join(OUT_DIR, "features.csv"), 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=out_headers)
        writer.writeheader()
        
        for i, row in enumerate(reader):
            out_row = {k: row.get(k, '') for k in base_fields}
            
            # Continuous
            msg_len = float(len(str(row.get('raw_message', ''))))
            cmd_len = float(len(str(row.get('command_line', ''))))
            
            out_row['msg_len_norm'] = (msg_len - means['msg']) / stds['msg']
            out_row['cmd_len_norm'] = (cmd_len - means['cmd']) / stds['cmd']
            
            cmd = str(row.get('command_line', '')).lower()
            out_row['cmd_entropy'] = entropy(cmd)
            
            # Behavioral binary
            pname = str(row.get('process_name', '')).lower()
            
            out_row['is_lolbin'] = 1 if any(lb in pname or lb in cmd for lb in lolbins) else 0
            out_row['is_powershell'] = 1 if 'powershell' in pname or 'powershell' in cmd or 'pwsh' in pname else 0
            out_row['is_cmd'] = 1 if 'cmd.exe' in pname or 'cmd.exe' in cmd else 0
            out_row['is_encoded_b64'] = 1 if '-enc' in cmd or '-encodedcommand' in cmd or re.search(r'[A-Za-z0-9+/]{40,}', cmd) else 0
            
            out_row['has_network_flags'] = 1 if any(x in cmd for x in ['ping', 'netstat', 'ipconfig', 'nslookup', 'curl', 'wget', 'http']) else 0
            out_row['has_recon_flags'] = 1 if any(x in cmd for x in ['whoami', 'systeminfo', 'net user', 'net group', 'nltest', 'tasklist', 'net localgroup']) else 0
            out_row['has_registry_flags'] = 1 if any(x in cmd for x in ['reg add', 'reg query', 'reg delete']) else 0
            out_row['has_suspicious_paths'] = 1 if any(x in cmd for x in ['c:\\temp', 'c:\\programdata', 'appdata\\local\\temp']) else 0
            out_row['has_execution_flags'] = 1 if any(x in cmd for x in ['invoke-expression', 'iex', 'bypass', 'hidden', '-nop']) else 0
            out_row['has_admin_shares'] = 1 if 'c$' in cmd or 'admin$' in cmd or 'ipc$' in cmd else 0
            
            # OHE Event Code
            ec = str(row.get('event_code', '')).strip()
            ec_idx = top_event_codes.index(ec) if ec in top_event_codes else len(top_event_codes)
            for j in range(len(top_event_codes) + 1): out_row[f'ec_{j}'] = 1 if j == ec_idx else 0
            
            # OHE Log Type
            lt = str(row.get('log_type', '')).strip()
            lt_idx = top_log_types.index(lt) if lt in top_log_types else len(top_log_types)
            for j in range(len(top_log_types) + 1): out_row[f'lt_{j}'] = 1 if j == lt_idx else 0
                
            # OHE Source
            src = str(row.get('source', '')).strip()
            src_idx = top_sources.index(src) if src in top_sources else len(top_sources)
            for j in range(len(top_sources) + 1): out_row[f'src_{j}'] = 1 if j == src_idx else 0
                
            writer.writerow(out_row)
            
    # Save Schema
    schema = {
        "num_features": len(feature_fields) + len(ohe_fields),
        "base_fields": base_fields,
        "feature_fields": feature_fields,
        "ohe_fields": ohe_fields,
        "vocabularies": {
            "event_code": top_event_codes,
            "log_type": top_log_types,
            "source": top_sources
        },
        "train_means": means,
        "train_stds": stds
    }
    with open(os.path.join(OUT_DIR, "feature_schema.json"), 'w') as f:
        json.dump(schema, f, indent=4)
        
    print(f"Feature V3 extraction complete. Total features: {schema['num_features']}")

if __name__ == "__main__":
    main()
