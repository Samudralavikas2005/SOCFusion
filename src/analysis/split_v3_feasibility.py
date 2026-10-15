import os
import csv
import json
import pandas as pd
import numpy as np
import random
from collections import defaultdict, Counter

def main():
    OUT_DIR = "data/analysis/split_v3_feasibility"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    NORM_CSV = "data/processed/normalized_events_v4.csv"
    LABEL_MAP = "data/processed/graphs_v1/label_mapping.json"
    SPLIT_V2_PART = "data/analysis/split_v2/host_partition.csv"
    
    with open(LABEL_MAP, 'r') as f:
        label_map = json.load(f)
        
    track_a_classes = sorted([
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ])
    
    print("Loading events...")
    df = pd.read_csv(NORM_CSV, usecols=['host', 'technique_id'], low_memory=False)
    
    # Filter for Track A only
    df = df[df['technique_id'].isin(track_a_classes)]
    df['host'] = df['host'].fillna("UNKNOWN_HOST").str.strip()
    df.loc[df['host'] == "", 'host'] = "UNKNOWN_HOST"
    
    # PHASE 1 - HOST/TECHNIQUE MATRIX
    print("Phase 1: Computing Host/Technique Matrix...")
    host_tech_matrix = pd.crosstab(df['host'], df['technique_id'])
    host_tech_matrix.to_csv(os.path.join(OUT_DIR, "host_technique_matrix.csv"))
    
    tech_host_stats = []
    for tech in track_a_classes:
        if tech not in host_tech_matrix.columns:
            continue
        
        counts = host_tech_matrix[tech]
        active_hosts = counts[counts > 0]
        total_events = active_hosts.sum()
        
        if total_events == 0:
            continue
            
        largest_host = active_hosts.idxmax()
        largest_count = active_hosts.max()
        largest_pct = (largest_count / total_events) * 100
        
        tech_host_stats.append({
            'technique': tech,
            'unique_hosts': len(active_hosts),
            'total_events': total_events,
            'largest_host': largest_host,
            'largest_host_events': largest_count,
            'largest_host_pct': largest_pct
        })
        
    pd.DataFrame(tech_host_stats).to_csv(os.path.join(OUT_DIR, "technique_host_statistics.csv"), index=False)
    
    # PHASE 2 - CURRENT SPLIT ANALYSIS
    print("Phase 2: Analyzing Current Split (V2)...")
    v2_parts = {}
    with open(SPLIT_V2_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            v2_parts[row['host']] = row['partition']
            
    df['v2_part'] = df['host'].map(lambda h: v2_parts.get(h, 'unknown'))
    
    v2_analysis = []
    for tech in track_a_classes:
        tech_df = df[df['technique_id'] == tech]
        total = len(tech_df)
        if total == 0: continue
        
        train_count = len(tech_df[tech_df['v2_part'] == 'train'])
        val_count = len(tech_df[tech_df['v2_part'] == 'val'])
        test_count = len(tech_df[tech_df['v2_part'] == 'test'])
        
        train_pct = train_count / total * 100
        val_pct = val_count / total * 100
        test_pct = test_count / total * 100
        
        train_test_ratio = train_count / test_count if test_count > 0 else (train_count if train_count > 0 else 0)
        
        v2_analysis.append({
            'technique': tech,
            'total': total,
            'train_count': train_count,
            'val_count': val_count,
            'test_count': test_count,
            'train_pct': train_pct,
            'val_pct': val_pct,
            'test_pct': test_pct,
            'train_test_ratio': train_test_ratio
        })
        
    pd.DataFrame(v2_analysis).to_csv(os.path.join(OUT_DIR, "current_split_analysis.csv"), index=False)
    
    # PHASE 3 & 4 - DETERMINE FEASIBILITY & OPTIMIZE
    print("Phase 3 & 4: Host-Level Optimization...")
    unique_hosts = df['host'].unique().tolist()
    random.seed(42)
    np.random.seed(42)
    
    def evaluate_candidate(host_assignments):
        train_counts = defaultdict(int)
        val_counts = defaultdict(int)
        test_counts = defaultdict(int)
        
        for h, part in host_assignments.items():
            if h in host_tech_matrix.index:
                row = host_tech_matrix.loc[h]
                for tech in track_a_classes:
                    if tech in row:
                        val = row[tech]
                        if part == 'train': train_counts[tech] += val
                        elif part == 'val': val_counts[tech] += val
                        elif part == 'test': test_counts[tech] += val
                        
        score = 0
        missing_penalties = 0
        balance_penalties = 0
        
        for tech in track_a_classes:
            t = train_counts[tech]
            v = val_counts[tech]
            te = test_counts[tech]
            
            tot = t + v + te
            if tot == 0: continue
            
            if t == 0: missing_penalties += 1000
            if v == 0: missing_penalties += 1000
            if te == 0: missing_penalties += 1000
            
            t_ratio = t / tot
            v_ratio = v / tot
            te_ratio = te / tot
            
            balance_penalties += abs(t_ratio - 0.70) * 100
            balance_penalties += abs(v_ratio - 0.15) * 100
            balance_penalties += abs(te_ratio - 0.15) * 100
            
        return missing_penalties + balance_penalties, train_counts, val_counts, test_counts
        
    candidates = []
    
    # Generate random candidates
    for i in range(10000):
        assignments = {}
        for h in unique_hosts:
            r = random.random()
            if r < 0.70:
                assignments[h] = 'train'
            elif r < 0.85:
                assignments[h] = 'val'
            else:
                assignments[h] = 'test'
                
        score, train_c, val_c, test_c = evaluate_candidate(assignments)
        
        num_missing = 0
        for tech in track_a_classes:
            if train_c[tech] == 0 or val_c[tech] == 0 or test_c[tech] == 0:
                num_missing += 1
                
        candidates.append({
            'candidate_id': i,
            'score': score,
            'assignments': assignments,
            'train_c': train_c,
            'val_c': val_c,
            'test_c': test_c,
            'num_missing': num_missing,
            'train_hosts': sum(1 for v in assignments.values() if v == 'train'),
            'val_hosts': sum(1 for v in assignments.values() if v == 'val'),
            'test_hosts': sum(1 for v in assignments.values() if v == 'test'),
        })
        
    candidates.sort(key=lambda x: x['score'])
    best_candidate = candidates[0]
    
    # PHASE 5 - CANDIDATE COMPARISON
    print("Phase 5: Candidate Comparison...")
    comp_rows = []
    for c in candidates[:50]:
        row = {
            'candidate_id': c['candidate_id'],
            'score': c['score'],
            'train_hosts': c['train_hosts'],
            'val_hosts': c['val_hosts'],
            'test_hosts': c['test_hosts'],
            'num_missing_classes': c['num_missing']
        }
        for tech in track_a_classes:
            row[f'{tech}_train'] = c['train_c'][tech]
            row[f'{tech}_val'] = c['val_c'][tech]
            row[f'{tech}_test'] = c['test_c'][tech]
        comp_rows.append(row)
        
    pd.DataFrame(comp_rows).to_csv(os.path.join(OUT_DIR, "candidate_split_comparison.csv"), index=False)
    
    # PHASE 6 - SELECT BEST VALID SPLIT
    print("Phase 6: Best Valid Split Analysis...")
    report = "# Split V3 Feasibility Report\n\n"
    
    valid_split_possible = best_candidate['num_missing'] == 0
    
    # Analyze mathematically impossible classes
    impossible_classes = []
    for st in tech_host_stats:
        if st['unique_hosts'] < 3:
            impossible_classes.append(st['technique'])
            
    if impossible_classes:
        report += "## Mathematical Impossibility\n"
        report += "The following classes appear on fewer than 3 unique hosts, making it **mathematically impossible** to have them represented in Train, Validation, and Test simultaneously under a strict host-isolated constraint:\n"
        for ic in impossible_classes:
            report += f"- {ic}\n"
        report += "\n"
        valid_split_possible = False
        
    # Specifically T1059.001 and T1053.005
    report += "## Extreme Imbalance Host Contributors\n"
    for st in tech_host_stats:
        if st['largest_host_pct'] > 50:
            report += f"- {st['technique']} is dominated by host {st['largest_host']} ({st['largest_host_pct']:.2f}% of {st['total_events']} events)\n"
            
    report += "\n## Best Discovered Candidate\n"
    report += f"- Missing partitions for classes: {best_candidate['num_missing']}\n"
    for tech in track_a_classes:
        t = best_candidate['train_c'][tech]
        v = best_candidate['val_c'][tech]
        te = best_candidate['test_c'][tech]
        report += f"- {tech}: Train={t}, Val={v}, Test={te}\n"
        
    report += "\n## Conclusion\n"
    if valid_split_possible:
        report += "VALID SPLIT V3 EXISTS — READY FOR GRAPH REBUILD\n"
        
        out_part = []
        for h, p in best_candidate['assignments'].items():
            out_part.append({'host': h, 'partition': p})
        pd.DataFrame(out_part).to_csv(os.path.join(OUT_DIR, "split_v3_host_partition.csv"), index=False)
        
        with open(os.path.join(OUT_DIR, "split_v3_config.json"), "w") as f:
            json.dump({
                "description": "Optimized Split V3",
                "train_hosts": best_candidate['train_hosts'],
                "val_hosts": best_candidate['val_hosts'],
                "test_hosts": best_candidate['test_hosts'],
                "missing_classes": best_candidate['num_missing']
            }, f, indent=4)
    else:
        report += "NO VALID BALANCED HOST-ISOLATED SPLIT EXISTS — ADDITIONAL HOST DATA REQUIRED\n"
        
    with open(os.path.join(OUT_DIR, "recommended_split_v3.md"), "w") as f:
        f.write(report)
        
    print(report)

if __name__ == "__main__":
    main()
