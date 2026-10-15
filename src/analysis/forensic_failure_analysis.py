import pandas as pd
import numpy as np
import os
import json
from scipy.stats import ks_2samp
from sklearn.metrics import mutual_info_score
from collections import defaultdict

def main():
    print("Loading normalized events and host partition...")
    df = pd.read_csv("data/processed/normalized_events_v4.csv")
    host_part = pd.read_csv("data/analysis/split_v2/host_partition.csv")
    
    # Merge partition info
    df = df.merge(host_part, on="host", how="left")
    
    # df.fillna('', inplace=True)  # removing general fillna
    
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    
    # Filter for Track A
    df_track_a = df[df["technique_id"].isin(TRACK_A_CLASSES)].copy()
    
    OUT_DIR = "data/analysis/forensic_analysis"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    report = []
    
    # 1. Feature extraction for analysis
    # Let's extract lengths and some categorical hashes
    df['msg_length'] = df['raw_message'].astype(str).str.len()
    df['cmd_length'] = df['command_line'].astype(str).str.len()
    df['ps_token_count'] = df['command_line'].apply(lambda x: len(str(x).split()))
    
    features_to_analyze = ['msg_length', 'cmd_length', 'ps_token_count', 'event_code', 'log_type', 'source', 'process_name']
    
    # Q1 & Q2: Distribution shifts (Train vs Test)
    print("Analyzing feature distribution shifts...")
    shifts = []
    train_df = df[df["partition"] == "train"]
    test_df = df[df["partition"] == "test"]
    val_df = df[df["partition"] == "val"]
    
    for feat in features_to_analyze:
        if feat in ['msg_length', 'cmd_length', 'ps_token_count']:
            train_vals = train_df[feat].values
            test_vals = test_df[feat].values
            stat, pval = ks_2samp(train_vals, test_vals)
            shifts.append({'feature': feat, 'ks_stat': stat, 'p_value': pval, 'type': 'continuous'})
        else:
            train_dist = train_df[feat].value_counts(normalize=True)
            test_dist = test_df[feat].value_counts(normalize=True)
            # Simple shift metric for categorical: total absolute difference
            all_keys = set(train_dist.keys()).union(set(test_dist.keys()))
            diff = 0
            for k in all_keys:
                diff += abs(train_dist.get(k, 0) - test_dist.get(k, 0))
            shifts.append({'feature': feat, 'tvd': diff / 2, 'type': 'categorical'})
            
    pd.DataFrame(shifts).to_csv(os.path.join(OUT_DIR, "distribution_shifts.csv"), index=False)
    
    # Q3, Q5 & Q6: Label correlations and fingerprinting
    print("Analyzing label correlations...")
    # Sample to speed up MI computation on Track A only
    train_track_a = df_track_a[df_track_a["partition"] == "train"]
    test_track_a = df_track_a[df_track_a["partition"] == "test"]
    sample_train = train_track_a.sample(min(50000, len(train_track_a)))
    sample_test = test_track_a.sample(min(50000, len(test_track_a)))
    
    correlations = []
    for feat in ['host', 'process_name', 'user', 'source', 'log_type', 'event_code', 'scenario']:
        feat_train = sample_train[feat].fillna('NaN').astype(str)
        feat_test = sample_test[feat].fillna('NaN').astype(str)
        mi_train = mutual_info_score(sample_train['technique_id'], feat_train)
        mi_test = mutual_info_score(sample_test['technique_id'], feat_test)
        correlations.append({'feature': feat, 'mi_train': mi_train, 'mi_test': mi_test})
        
    pd.DataFrame(correlations).to_csv(os.path.join(OUT_DIR, "label_correlations.csv"), index=False)
    
    # Q4: Track A technique details
    print("Analyzing technique distributions...")
    tech_details = []
    for tech in TRACK_A_CLASSES:
        tech_df = df[df["technique_id"] == tech]
        train_count = len(tech_df[tech_df["partition"] == "train"])
        val_count = len(tech_df[tech_df["partition"] == "val"])
        test_count = len(tech_df[tech_df["partition"] == "test"])
        host_count = tech_df['host'].nunique()
        
        tech_details.append({
            'technique': tech,
            'train_count': train_count,
            'val_count': val_count,
            'test_count': test_count,
            'host_count': host_count
        })
    pd.DataFrame(tech_details).to_csv(os.path.join(OUT_DIR, "technique_counts.csv"), index=False)
    
    # Q7: Cross-host feature distribution for the same technique
    print("Analyzing cross-host feature distribution for same technique...")
    cross_host = []
    for tech in TRACK_A_CLASSES:
        tech_df = df[df["technique_id"] == tech]
        hosts = tech_df['host'].unique()
        if len(hosts) > 1:
            # Let's take up to 3 hosts and compare event_code distributions
            top_hosts = tech_df['host'].value_counts().head(3).index
            for h in top_hosts:
                h_df = tech_df[tech_df['host'] == h]
                top_evt = h_df['event_code'].value_counts(normalize=True).head(1)
                top_proc = h_df['process_name'].value_counts(normalize=True).head(1)
                
                evt_val = f"{top_evt.index[0]} ({top_evt.values[0]:.2f})" if not top_evt.empty else "N/A"
                proc_val = f"{top_proc.index[0]} ({top_proc.values[0]:.2f})" if not top_proc.empty else "N/A"
                
                cross_host.append({
                    'technique': tech,
                    'host': h,
                    'top_event_code': evt_val,
                    'top_process_name': proc_val,
                    'host_event_count': len(h_df)
                })
                
    pd.DataFrame(cross_host).to_csv(os.path.join(OUT_DIR, "cross_host_distributions.csv"), index=False)
    print("Analysis complete. Check data/analysis/forensic_analysis/")

if __name__ == "__main__":
    main()
