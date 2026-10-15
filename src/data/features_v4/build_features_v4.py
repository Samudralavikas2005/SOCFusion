import csv
import sys
import os
import math
import json
import re
from collections import Counter
import numpy as np
import pandas as pd

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
    OUT_DIR = "data/processed/features_v4"
    ANALYSIS_DIR = "data/analysis/features_v4"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    host_to_part = {}
    with open(HOST_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_to_part[row['host']] = row['partition']
            
    lolbins = {"certutil", "bitsadmin", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "wmic", "powershell", "cmd", "pwsh"}
    
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
    
    print("Pass 2: Building features...")
    
    base_fields = ['event_id', 'timestamp', 'host', 'user', 'process_id', 'process_name', 
                   'process_path', 'command_line', 'event_code', 'log_type', 'source', 
                   'technique_id', 'scenario', 'source_file', 'partition']
                   
    feature_fields = [
        'msg_len_norm', 'cmd_len_norm', 'msg_entropy', 'cmd_entropy',
        'is_lolbin', 'is_powershell', 'is_cmd', 'is_encoded_b64',
        'has_network_flags', 'has_recon_flags', 'has_registry_flags',
        'has_suspicious_paths', 'has_execution_flags', 'has_admin_shares',
        # Missing indicators
        'missing_command_line', 'missing_process_name', 'missing_user', 'missing_host',
        # Specific semantic behaviors
        'is_scheduled_task', 'is_service_creation', 'is_process_creation', 'is_authentication',
        'is_privilege_elevation'
    ]
    
    ohe_fields = []
    for i in range(len(top_event_codes) + 1): ohe_fields.append(f'ec_{i}')
    for i in range(len(top_log_types) + 1): ohe_fields.append(f'lt_{i}')
    for i in range(len(top_sources) + 1): ohe_fields.append(f'src_{i}')
    
    out_headers = base_fields + feature_fields + ohe_fields
    
    stats_rows = []
    
    with open(IN_CSV, 'r') as f_in, open(os.path.join(OUT_DIR, "features.csv"), 'w', newline='') as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=out_headers)
        writer.writeheader()
        
        for row in reader:
            host = row.get('host', '').strip()
            if not host: host = 'UNKNOWN_HOST'
            part = host_to_part.get(host, 'unknown')
            
            out_row = {k: row.get(k, '') for k in base_fields}
            out_row['partition'] = part
            
            msg = str(row.get('raw_message', '')).lower()
            cmd = str(row.get('command_line', '')).lower()
            pname = str(row.get('process_name', '')).lower()
            
            msg_len = float(len(msg))
            cmd_len = float(len(cmd))
            
            out_row['msg_len_norm'] = (msg_len - means['msg']) / stds['msg']
            out_row['cmd_len_norm'] = (cmd_len - means['cmd']) / stds['cmd']
            
            out_row['msg_entropy'] = entropy(msg)
            out_row['cmd_entropy'] = entropy(cmd)
            
            # Missing indicators
            out_row['missing_command_line'] = 1 if not cmd else 0
            out_row['missing_process_name'] = 1 if not pname else 0
            out_row['missing_user'] = 1 if not row.get('user', '').strip() else 0
            out_row['missing_host'] = 1 if not row.get('host', '').strip() else 0
            
            # Combine cmd and msg for behavioral flags because powershell logs store cmd in msg
            combined_text = f"{cmd} {msg}"
            
            out_row['is_lolbin'] = 1 if any(lb in pname or lb in combined_text for lb in lolbins) else 0
            out_row['is_powershell'] = 1 if 'powershell' in pname or 'powershell' in combined_text or 'pwsh' in pname else 0
            out_row['is_cmd'] = 1 if 'cmd.exe' in pname or 'cmd.exe' in combined_text else 0
            out_row['is_encoded_b64'] = 1 if '-enc' in combined_text or '-encodedcommand' in combined_text or re.search(r'[A-Za-z0-9+/]{40,}', combined_text) else 0
            
            out_row['has_network_flags'] = 1 if any(x in combined_text for x in ['ping', 'netstat', 'ipconfig', 'nslookup', 'curl', 'wget', 'http']) else 0
            out_row['has_recon_flags'] = 1 if any(x in combined_text for x in ['whoami', 'systeminfo', 'net user', 'net group', 'nltest', 'tasklist', 'net localgroup']) else 0
            out_row['has_registry_flags'] = 1 if any(x in combined_text for x in ['reg add', 'reg query', 'reg delete', 'registry::']) else 0
            out_row['has_suspicious_paths'] = 1 if any(x in combined_text for x in ['c:\\temp', 'c:\\programdata', 'appdata\\local\\temp']) else 0
            out_row['has_execution_flags'] = 1 if any(x in combined_text for x in ['invoke-expression', 'iex', 'bypass', 'hidden', '-nop']) else 0
            out_row['has_admin_shares'] = 1 if 'c$' in combined_text or 'admin$' in combined_text or 'ipc$' in combined_text else 0
            
            ec = str(row.get('event_code', '')).strip()
            out_row['is_scheduled_task'] = 1 if ec in ['4698', '4702'] or 'schtasks' in combined_text else 0
            out_row['is_service_creation'] = 1 if ec in ['7045'] or 'sc create' in combined_text else 0
            out_row['is_process_creation'] = 1 if ec in ['4688', '1'] else 0
            out_row['is_authentication'] = 1 if ec in ['4624', '4625', '4768', '4769', '4776'] else 0
            out_row['is_privilege_elevation'] = 1 if ec in ['4672'] else 0
            
            ec_idx = top_event_codes.index(ec) if ec in top_event_codes else len(top_event_codes)
            for j in range(len(top_event_codes) + 1): out_row[f'ec_{j}'] = 1 if j == ec_idx else 0
            
            lt = str(row.get('log_type', '')).strip()
            lt_idx = top_log_types.index(lt) if lt in top_log_types else len(top_log_types)
            for j in range(len(top_log_types) + 1): out_row[f'lt_{j}'] = 1 if j == lt_idx else 0
                
            src = str(row.get('source', '')).strip()
            src_idx = top_sources.index(src) if src in top_sources else len(top_sources)
            for j in range(len(top_sources) + 1): out_row[f'src_{j}'] = 1 if j == src_idx else 0
                
            writer.writerow(out_row)
            stats_rows.append(out_row)
            
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
        
    print(f"Feature V4 extraction complete. Total features: {schema['num_features']}")
    
    # Check shift
    print("Checking Train/Val/Test Distribution Shift...")
    df = pd.DataFrame(stats_rows)
    report = "# Feature V4 Report\n\n"
    report += f"Total features: {schema['num_features']}\n\n"
    
    for f in feature_fields:
        report += f"## {f}\n"
        train_mean = df[df['partition'] == 'train'][f].mean()
        val_mean = df[df['partition'] == 'val'][f].mean()
        test_mean = df[df['partition'] == 'test'][f].mean()
        report += f"- Train Mean: {train_mean:.4f}\n"
        report += f"- Val Mean:   {val_mean:.4f}\n"
        report += f"- Test Mean:  {test_mean:.4f}\n\n"
        
    with open(os.path.join(ANALYSIS_DIR, "feature_v4_report.md"), "w") as f:
        f.write(report)
        
    print("Distribution shift report saved.")

if __name__ == "__main__":
    main()
