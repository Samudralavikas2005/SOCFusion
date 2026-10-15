import os
import csv
import json
from collections import defaultdict

def main():
    MAPPING_FILE = "data/analysis/mitre_mapping/mapping_examples.csv"
    OUT_DIR = "data/analysis/detection_gaps"
    
    os.makedirs(OUT_DIR, exist_ok=True)
    
    false_negatives = []
    technique_failures = defaultdict(int)
    technique_totals = defaultdict(int)
    
    with open(MAPPING_FILE, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            true_tech = row["true_technique"]
            pred_tech = row["predicted_technique"]
            
            technique_totals[true_tech] += 1
            
            if true_tech != pred_tech:
                technique_failures[true_tech] += 1
                false_negatives.append({
                    "chain_id": row["chain_id"],
                    "true_technique": true_tech,
                    "predicted_technique": pred_tech,
                    "num_events": row["num_events"],
                    "confidence": row["confidence"]
                })
                
    # Vulnerable techniques
    vuln_techs = []
    for tech, fails in technique_failures.items():
        total = technique_totals[tech]
        miss_rate = fails / total
        vuln_techs.append({
            "technique": tech,
            "total_chains": total,
            "failed_chains": fails,
            "miss_rate": round(miss_rate, 4)
        })
        
    vuln_techs.sort(key=lambda x: x["miss_rate"], reverse=True)
    
    with open(os.path.join(OUT_DIR, "vulnerable_techniques.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["technique", "total_chains", "failed_chains", "miss_rate"])
        writer.writeheader()
        writer.writerows(vuln_techs)
        
    with open(os.path.join(OUT_DIR, "false_negatives.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["chain_id", "true_technique", "predicted_technique", "num_events", "confidence"])
        writer.writeheader()
        writer.writerows(false_negatives)
        
    report = f"""# Detection Gap Analysis

## Overview
Analysis of the attack chains where the final model (GAT V6) misclassified the behavior.

## Key Deficiencies
- Total False Negative Chains: {len(false_negatives)}
- Total Evaluated Chains: {sum(technique_totals.values())}

### Most Vulnerable Techniques
"""
    for v in vuln_techs[:5]:
        report += f"- **{v['technique']}**: Missed {v['failed_chains']}/{v['total_chains']} chains (Miss Rate: {v['miss_rate']*100:.2f}%)\n"
        
    report += """
## Hypothesis for Remaining Deficiencies
While the final GAT V6 model using domain-invariant features generalized much better than GAT V3, some highly imbalanced classes are still missed. The graph bottleneck was resolved by restricting to Process-tree structures.

FINAL STATUS: GAP ANALYSIS COMPLETE
"""
    with open(os.path.join(OUT_DIR, "gap_analysis_report.md"), "w") as f:
        f.write(report)
        
    print("Gap analysis complete.")

if __name__ == "__main__":
    main()
