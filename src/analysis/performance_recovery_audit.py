import os
import csv
import json
import torch
import pandas as pd
import numpy as np
from collections import Counter
import pickle

def main():
    OUT_DIR = "data/analysis/performance_recovery"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    # 1. Label Alignment Audit
    print("Checking label alignment...")
    NORM_CSV = "data/processed/normalized_events_v4.csv"
    FEAT_CSV = "data/processed/features_v4/features.csv"
    LABEL_MAP = "data/processed/graphs_v1/label_mapping.json"
    
    with open(LABEL_MAP, 'r') as f:
        label_map = json.load(f)
        
    track_a_classes = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in track_a_classes]
    
    norm_labels = []
    norm_hosts = []
    norm_scenarios = []
    with open(NORM_CSV, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row.get('technique_id', '')
            norm_labels.append(label_map.get(tid, -1))
            norm_hosts.append(row.get('host', 'UNKNOWN_HOST'))
            norm_scenarios.append(row.get('scenario', ''))
            
    feat_labels = []
    feat_hosts = []
    feat_scenarios = []
    with open(FEAT_CSV, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            tid = row.get('technique_id', '')
            feat_labels.append(label_map.get(tid, -1))
            feat_hosts.append(row.get('host', 'UNKNOWN_HOST'))
            feat_scenarios.append(row.get('scenario', ''))
            
    # Check 1: Row count
    assert len(norm_labels) == len(feat_labels), f"Row count mismatch: {len(norm_labels)} != {len(feat_labels)}"
    
    # Check 2: Label matches
    mismatch_count = 0
    for i in range(len(norm_labels)):
        if norm_labels[i] != feat_labels[i]:
            mismatch_count += 1
    
    alignment_report = []
    alignment_report.append(f"Row count: {len(norm_labels)}")
    alignment_report.append(f"Label mismatches between norm and feat: {mismatch_count}")
    
    # Check 3: Graph node alignment
    graphs = {}
    for part in ['train', 'val', 'test']:
        with open(f"data/processed/graphs_v5/{part}_data.pt", 'rb') as f:
            graphs[part] = pickle.load(f)
            
    # Reconstruct what the graph expects
    HOST_PART = "data/analysis/split_v2/host_partition.csv"
    host_to_part = {}
    with open(HOST_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_to_part[row['host']] = row['partition']
            
    part_lists = {'train': [], 'val': [], 'test': []}
    for i in range(len(feat_labels)):
        host = feat_hosts[i].strip()
        if not host: host = 'UNKNOWN_HOST'
        part = host_to_part.get(host)
        if part in part_lists:
            part_lists[part].append(feat_labels[i])
            
    graph_mismatches = {}
    for part in ['train', 'val', 'test']:
        expected = part_lists[part]
        actual = graphs[part]['nodes']['Event']['y']
        
        if len(expected) != len(actual):
            graph_mismatches[part] = f"Length mismatch: {len(expected)} vs {len(actual)}"
        else:
            mismatches = sum(1 for e, a in zip(expected, actual) if e != a)
            graph_mismatches[part] = f"Mismatches: {mismatches}"
            
    for k, v in graph_mismatches.items():
        alignment_report.append(f"Graph alignment for {k}: {v}")
        
    with open(os.path.join(OUT_DIR, "label_integrity.csv"), "w") as f:
        f.write("\n".join(alignment_report))
        
    # Phase 1 Data Audit
    print("Performing data audit...")
    audit_data = []
    df = pd.read_csv(FEAT_CSV, low_memory=False)
    
    for c in track_a_classes:
        c_mapped = label_map[c]
        c_df = df[df['technique_id'] == c]
        
        train_c = c_df[c_df['partition'] == 'train']
        val_c = c_df[c_df['partition'] == 'val']
        test_c = c_df[c_df['partition'] == 'test']
        
        for part_name, part_df in [('train', train_c), ('val', val_c), ('test', test_c)]:
            audit_data.append({
                'class': c,
                'partition': part_name,
                'events': len(part_df),
                'hosts': part_df['host'].nunique(),
                'processes': part_df['process_id'].nunique(),
                'msg_len_mean': part_df['msg_len_norm'].mean() if not part_df.empty else 0,
                'is_powershell_pct': part_df['is_powershell'].mean() if not part_df.empty else 0,
                'has_network_pct': part_df['has_network_flags'].mean() if not part_df.empty else 0
            })
            
    audit_df = pd.DataFrame(audit_data)
    audit_df.to_csv(os.path.join(OUT_DIR, "class_host_distribution.csv"), index=False)
    
    # Train test shift
    shift_data = []
    for c in track_a_classes:
        train_h = audit_df[(audit_df['class'] == c) & (audit_df['partition'] == 'train')]['hosts'].values[0]
        test_h = audit_df[(audit_df['class'] == c) & (audit_df['partition'] == 'test')]['hosts'].values[0]
        train_e = audit_df[(audit_df['class'] == c) & (audit_df['partition'] == 'train')]['events'].values[0]
        test_e = audit_df[(audit_df['class'] == c) & (audit_df['partition'] == 'test')]['events'].values[0]
        
        shift_data.append({
            'class': c,
            'train_hosts': train_h,
            'test_hosts': test_h,
            'train_events': train_e,
            'test_events': test_e
        })
        
    pd.DataFrame(shift_data).to_csv(os.path.join(OUT_DIR, "train_test_shift.csv"), index=False)
    print("Audit complete.")
    
if __name__ == "__main__":
    main()
