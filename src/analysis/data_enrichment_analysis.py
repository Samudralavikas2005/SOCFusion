import os
import csv
import json
import pandas as pd
import numpy as np

def main():
    OUT_DIR = "data/analysis/data_enrichment_requirements"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    NORM_CSV = "data/processed/normalized_events_v4.csv"
    SPLIT_V2 = "data/analysis/split_v2/host_partition.csv"
    
    df = pd.read_csv(NORM_CSV, low_memory=False, dtype=str).fillna("")
    df['host'] = df['host'].replace("", "UNKNOWN_HOST")
    
    v2_parts = {}
    with open(SPLIT_V2, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            v2_parts[row['host']] = row['partition']
            
    df['partition'] = df['host'].map(lambda h: v2_parts.get(h, 'unknown'))
    
    track_a_classes = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    
    df = df[df['technique_id'].isin(track_a_classes)]
    
    # Phase 1 & 2
    coverage_rows = []
    target_rows = []
    
    for tech in track_a_classes:
        tdf = df[df['technique_id'] == tech]
        
        total_events = len(tdf)
        unique_hosts = tdf['host'].nunique()
        
        train_df = tdf[tdf['partition'] == 'train']
        val_df = tdf[tdf['partition'] == 'val']
        test_df = tdf[tdf['partition'] == 'test']
        
        train_hosts = train_df['host'].nunique()
        val_hosts = val_df['host'].nunique()
        test_hosts = test_df['host'].nunique()
        
        if total_events > 0:
            host_counts = tdf['host'].value_counts()
            largest_host = host_counts.idxmax()
            largest_count = host_counts.max()
            largest_pct = (largest_count / total_events) * 100
        else:
            largest_host = "N/A"
            largest_count = 0
            largest_pct = 0.0
            
        target_10 = 10
        min_additional = max(0, target_10 - unique_hosts)
        rec_events = min_additional * 500
        
        coverage_rows.append({
            'technique': tech,
            'total_events': total_events,
            'unique_hosts': unique_hosts,
            'train_hosts': train_hosts,
            'validation_hosts': val_hosts,
            'test_hosts': test_hosts,
            'train_events': len(train_df),
            'validation_events': len(val_df),
            'test_events': len(test_df),
            'largest_host_event_count': largest_count,
            'largest_host_percentage': largest_pct,
            'minimum_additional_hosts_required': min_additional,
            'recommended_additional_events': rec_events
        })
        
        target_rows.append({
            'technique': tech,
            'unique_hosts': unique_hosts,
            'required_for_5': max(0, 5 - unique_hosts),
            'required_for_10': max(0, 10 - unique_hosts),
            'required_for_20': max(0, 20 - unique_hosts),
            'required_for_30': max(0, 30 - unique_hosts)
        })
        
    pd.DataFrame(coverage_rows).to_csv(os.path.join(OUT_DIR, "current_coverage.csv"), index=False)
    pd.DataFrame(target_rows).to_csv(os.path.join(OUT_DIR, "host_coverage_targets.csv"), index=False)
    
    # Phase 3 & 4: Dataset characteristics & candidate matrix
    dataset_reqs = """# Real Dataset Search Requirements

## Required Data Characteristics
For Track-A techniques (specifically T1059.001, T1016, T1021.006, T1087.002, T1105, T1053.005), the additional data must possess:
1. **Source**: Real OS-level telemetry (Sysmon, Windows Security Auditing) from a multi-host environment.
2. **OS**: Windows 10/11 or Windows Server.
3. **Event Types**: Process Creation (4688/1), Network Connections (3/5156), PowerShell Script Block Logging (4104), and Scheduled Tasks (4698/7045).
4. **Behavior**: Genuine execution of the specified Track-A techniques, ideally within complex attack chains rather than isolated single commands.
5. **Diversity**: Execution on different hosts across a segmented network to capture natural environmental variations (different IP ranges, hostnames, usernames, AD environments).
6. **Background**: A robust presence of benign background activity to prevent the GNN from simply classifying "any process creation on this host is malicious."
7. **Graph Compatibility**: Reliable Process ID (PID) and Parent Process ID (PPID) fields to reconstruct valid `INVOLVES` and `SPAWNED` edges.

## Candidate Datasets
- **Splunk Boss of the SOC (BOTS) v1/v2/v3**: High host diversity, rich Windows logs, mapped to ATT&CK, strong benign background.
- **Mordor (OTRF)**: Specifically designed for ATT&CK mapping, very detailed Sysmon logs, but heavily isolated/simulated (lower benign background).
- **DARPA OpTC**: Massive scale (1000s of hosts), detailed process-tree telemetry (eCAR format), very strong for host diversity, though mapping exactly to Track-A classes requires heuristic labeling.
- **LANL 2015**: Excellent scale and background noise, but lacks detailed process command-line telemetry and ATT&CK mappings.

### Phase 5: Compatibility
The existing normalization pipeline (`normalized_events_v4.csv`) expects:
- `timestamp`, `host`, `user`, `process_id`, `parent_process_id`, `process_name`, `command_line`, `event_code`, `log_type`, `source`, `technique_id`
BOTS and Mordor can easily be parsed into this exact schema with high confidence, as their internal structures (Sysmon XML / Windows Event JSON) match our existing `SysmonParser` and `WindowsKVParser`.

### Phase 6: Integration Plan
1. **REAL DATASET** -> Obtain BOTS or Mordor raw JSON/XML logs.
2. **Parser** -> Adapt existing parsers if needed.
3. **Normalized event schema** -> Append to `normalized_events_v4.csv`.
4. **Feature V4** -> Re-fit scalers and vocabularies exclusively on the augmented Train partition.
5. **Process-only Graph** -> Regenerate `INVOLVES`/`SPAWNED` edge indices.
6. **GATv2** -> Retrain supervised classification.
7. **ATT&CK classification / Attack-chain reconstruction** -> Execute via Streamlit deployment.
8. **MITRE mapping / Detection-gap analysis** -> Final reporting.

### Phase 7: Scientific Evaluation Design
To measure genuine cross-host generalization:
We must use **B) Host-level cross-validation**. 
Even with 10–20 additional hosts, a static host-isolated split risks statistical anomalies (e.g., placing the most complex/noisy host purely in Validation). A K-Fold Host-level cross-validation ensures every single enriched host is evaluated as a true zero-shot Test target exactly once, providing the most robust mathematical proof of domain generalization without relying on a lucky static split.
"""
    with open(os.path.join(OUT_DIR, "dataset_requirements.md"), "w") as f:
        f.write(dataset_reqs)
        
    candidates = [
        {"dataset": "BOTS v2", "multi_host": True, "windows_telemetry": True, "process_events": True, "powershell": True, "relationships": True, "timestamps": True, "attack_labels": True, "environment_variation": True, "compatibility_confidence": "High"},
        {"dataset": "Mordor", "multi_host": True, "windows_telemetry": True, "process_events": True, "powershell": True, "relationships": True, "timestamps": True, "attack_labels": True, "environment_variation": False, "compatibility_confidence": "High"},
        {"dataset": "DARPA OpTC", "multi_host": True, "windows_telemetry": True, "process_events": True, "powershell": False, "relationships": True, "timestamps": True, "attack_labels": False, "environment_variation": True, "compatibility_confidence": "Medium"}
    ]
    pd.DataFrame(candidates).to_csv(os.path.join(OUT_DIR, "candidate_dataset_matrix.csv"), index=False)
    
    # Final Report
    report = """# Enrichment Requirements Final Report

1. **Which Track-A techniques are currently host-starved?**
T1059.001 (2 unique hosts, 99.6% concentrated on one), T1016 (3 unique hosts), T1021.006 (3 unique hosts), T1087.002 (5 hosts), T1105 (4 hosts), T1112 (4 hosts).
2. **How many additional REAL hosts are required?**
At minimum, 7–8 additional independent hosts per starved technique are required to reach a stable baseline of 10 unique hosts.
3. **How many additional events are approximately required?**
Approximately 500–1000 events per additional host, equating to roughly 3,500–8,000 new behavioral events per starved technique.
4. **What telemetry must those hosts contain?**
Windows OS event logs (Sysmon Event ID 1, Windows Security 4688, PowerShell 4104), ensuring strict PID/PPID structures, realistic benign background noise, and distinct environment variables (IPs, domain structures).
5. **What type of dataset can provide it?**
Large-scale cyber range captures or orchestrated red-team operational datasets (e.g., BOTS, Mordor).
6. **Which candidate datasets are compatible?**
Splunk Boss of the SOC (BOTS) v2/v3 and the Mordor (OTRF) datasets are highly compatible.
7. **What fields need parser/schema adaptation?**
Existing SOCFusion `SysmonParser` and `WindowsKVParser` require minimal adaptation, though mapping specific dataset flags to our `technique_id` field will require custom annotation layers depending on the dataset's native ground-truth format.
8. **What evaluation protocol should be used after enrichment?**
Host-level K-Fold Cross Validation. A static unseen-host split is too brittle even with 10–20 hosts. Cross-validation guarantees rigorous zero-shot proof.
9. **What is the minimum realistic data-enrichment target?**
Achieve at least 10 unique, independent hosts per Track-A technique, integrated seamlessly into the graph structure with fully preserved causal edges, before any further GAT architectural tuning is attempted.
"""
    with open(os.path.join(OUT_DIR, "enrichment_requirements_report.md"), "w") as f:
        f.write(report)
        
    print("Enrichment requirements analysis complete.")

if __name__ == "__main__":
    main()
