import os
import csv
import json

IN_DIR = "data/analysis/split_audit"
OUT_DIR = "data/analysis/split_design_v2"
os.makedirs(OUT_DIR, exist_ok=True)

# 1. Load data
classes = []
with open(os.path.join(IN_DIR, "class_by_split.csv"), "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        classes.append(row)
        
host_dist = []
with open(os.path.join(IN_DIR, "technique_host_distribution.csv"), "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        host_dist.append(row)

host_matrix = []
with open(os.path.join(IN_DIR, "host_technique_matrix.csv"), "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        host_matrix.append(row)
        
host_by_split = []
with open(os.path.join(IN_DIR, "host_by_split.csv"), "r") as f:
    reader = csv.DictReader(f)
    for row in reader:
        host_by_split.append(row)

# Total events calculation
train_events = sum(int(c["train"]) for c in classes)
val_events = sum(int(c["val"]) for c in classes)
test_events = sum(int(c["test"]) for c in classes)
total_events = train_events + val_events + test_events

# Identify single-host techniques
single_host_techs = [row for row in host_dist if int(row["num_distinct_hosts"]) == 1]
single_host_indices = [int(row["class_idx"]) for row in single_host_techs]

# Determine supervised classes (those with >1 host)
supervised_classes = [c for c in classes if int(c["class_idx"]) not in single_host_indices]
zero_shot_classes = [c for c in classes if int(c["class_idx"]) in single_host_indices]

# Save supervised class coverage
with open(os.path.join(OUT_DIR, "supervised_class_coverage.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["class_idx", "technique", "train", "val", "test", "num_distinct_hosts"])
    writer.writeheader()
    for c in supervised_classes:
        h_info = next(h for h in host_dist if h["class_idx"] == c["class_idx"])
        writer.writerow({
            "class_idx": c["class_idx"],
            "technique": c["technique"],
            "train": c["train"],
            "val": c["val"],
            "test": c["test"],
            "num_distinct_hosts": h_info["num_distinct_hosts"]
        })
        
# Save zero-shot class coverage
with open(os.path.join(OUT_DIR, "zero_shot_class_coverage.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["class_idx", "technique", "train", "val", "test", "num_distinct_hosts"])
    writer.writeheader()
    for c in zero_shot_classes:
        h_info = next(h for h in host_dist if h["class_idx"] == c["class_idx"])
        writer.writerow({
            "class_idx": c["class_idx"],
            "technique": c["technique"],
            "train": c["train"],
            "val": c["val"],
            "test": c["test"],
            "num_distinct_hosts": h_info["num_distinct_hosts"]
        })

# Copy host technique matrix
import shutil
shutil.copy(os.path.join(IN_DIR, "host_technique_matrix.csv"), os.path.join(OUT_DIR, "host_technique_matrix.csv"))

# Candidate Splits Analysis
candidates = [
    {
        "option": "A. Current strict host split",
        "train_hosts": sum(1 for h in host_by_split if h["split"] == "train"),
        "val_hosts": sum(1 for h in host_by_split if h["split"] == "val"),
        "test_hosts": sum(1 for h in host_by_split if h["split"] == "test"),
        "train_events": train_events,
        "val_events": val_events,
        "test_events": test_events,
        "technique_coverage": "15 classes across dataset, but incomplete per split.",
        "absent_from_train": "T1018",
        "absent_from_val": "T1003.001, T1003.003, T1016, T1018, T1047, T1059.001, T1059.003, T1068, T1105, T1558.003",
        "absent_from_test": "T1003.001, T1003.003, T1016, T1047, T1059.003, T1068, T1112",
        "leakage_risk": "None (Strict host isolation)",
        "supervised_suitability": "Poor (85.4% of test events are unseen classes).",
        "zero_shot_suitability": "Excellent. Tests strict generalization."
    },
    {
        "option": "C. Host-isolated split with rare single-host techniques excluded from supervised metric",
        "train_hosts": sum(1 for h in host_by_split if h["split"] == "train"),
        "val_hosts": sum(1 for h in host_by_split if h["split"] == "val"),
        "test_hosts": sum(1 for h in host_by_split if h["split"] == "test"),
        "train_events": train_events,
        "val_events": val_events,
        "test_events": test_events,
        "technique_coverage": "Evaluates Macro-F1 only on the 12 classes with >1 host.",
        "absent_from_train": "None of the 12 supervised classes.",
        "absent_from_val": "Many (since validation only has 4 classes).",
        "absent_from_test": "Some of the 12 supervised classes.",
        "leakage_risk": "None (Strict host isolation)",
        "supervised_suitability": "Fair. Evaluates on 12 classes, avoiding 0-shot penalties, but val/test sets still lack coverage of all 12 classes.",
        "zero_shot_suitability": "Good. Tracks single-host techniques separately."
    },
    {
        "option": "B. Host-isolated class-aware split",
        "train_hosts": "Re-assigned",
        "val_hosts": "Re-assigned",
        "test_hosts": "Re-assigned",
        "train_events": "~70%",
        "val_events": "~15%",
        "test_events": "~15%",
        "technique_coverage": "Maximizes coverage of the 12 multi-host classes across all splits.",
        "absent_from_train": "None of the 12 supervised classes.",
        "absent_from_val": "Minimized.",
        "absent_from_test": "Minimized.",
        "leakage_risk": "None (Strict host isolation)",
        "supervised_suitability": "Excellent for the 12 multi-host classes.",
        "zero_shot_suitability": "Good. Single-host classes are randomly assigned to a split."
    }
]

with open(os.path.join(OUT_DIR, "candidate_split_comparison.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=candidates[0].keys())
    writer.writeheader()
    writer.writerows(candidates)
    
report_content = """# SPLIT DESIGN REPORT

## 1. Problem Statement
The dataset contains 15 ATT&CK techniques. Three of these techniques (T1018, T1059.003, T1068) occur on exactly 1 host each in the entire dataset. 
Under strict host isolation, a host cannot cross partitions. Therefore, it is **mathematically impossible** for these three techniques to be represented in both the training set and the test set simultaneously. 
If they are placed in training, they cannot be evaluated. If placed in testing, they become zero-shot classes, which destroys standard supervised classification metrics (as seen with T1018 constituting 85.4% of the current test set).

## 2. Solution: Two-Track Evaluation
To maintain strict host isolation (preventing graph data leakage) while enabling scientifically valid measurements, the evaluation must be split into two tracks:

### TRACK A: Supervised Evaluation (12 Classes)
- **Supervised Classes**: The 12 techniques that occur on >1 host.
- **Metric**: 12-Class Macro-F1.
- **Data Condition**: Hosts must be re-partitioned (Host-Isolated Class-Aware Split) to ensure all 12 supervised techniques are present in the training set, and as many as mathematically possible are represented in validation and testing. 

### TRACK B: Zero-Shot / Unseen Host Generalization (All 15 Classes)
- **Zero-Shot Classes**: The 3 single-host techniques (T1018, T1059.003, T1068), plus any multi-host techniques that intentionally have their hosts withheld from training.
- **Metric**: Test Accuracy/F1 specifically calculated on the unseen classes, or whole-dataset Macro-F1 recognizing the zero-shot nature.
- **Data Condition**: The current strict host split serves this purpose perfectly, evaluating how the GNN behaves when 85.4% of events belong to an unseen technique.

## 3. Leakage Controls
- Both tracks maintain **strict host isolation**.
- No event-level random splitting is permitted.
- No edges will bridge train/validation/test partitions.
"""
with open(os.path.join(OUT_DIR, "split_design_report.md"), "w") as f:
    f.write(report_content)
    
recommended = """# RECOMMENDED EVALUATION PROTOCOL

## 1. Recommended Track A Split (Supervised)
**Host-Isolated Class-Aware Split**
- **Action**: Re-partition the hosts. Distribute hosts such that the 12 multi-host techniques are maximally represented across train, validation, and test sets. 
- **Exclusion**: The 3 single-host techniques (T1018, T1059.003, T1068) are structurally excluded from the 12-class Macro-F1 calculation, as they cannot mathematically be supervised and evaluated.

## 2. Recommended Track B Split (Zero-Shot)
**Current Strict Host Split**
- **Action**: Use the existing baseline split (`train_data.pt`, `val_data.pt`, `test_data.pt`) exactly as it is.
- **Evaluation**: Measure the model's predictive behavior specifically on T1018 (Class 3), which represents an entirely unseen attack morphology. 

## 3. Supervised vs. Zero-Shot Technique Sets
- **Supervised Classes (12)**: T1003.001, T1003.003, T1016, T1021.006, T1047, T1053.005, T1059.001, T1087.002, T1105, T1112, T1558.003, T1562.001
- **Zero-Shot-Only Classes (3)**: T1018, T1059.003, T1068

## 4. Exact Reason for the Distinction
A technique that occurs on only 1 host across the entire dataset mathematically cannot be placed in a training set and an evaluation set simultaneously without violating host-isolation. Violating host-isolation introduces graph data leakage. Thus, these 3 classes must either be strictly training-only (never evaluated) or test-only (zero-shot). 

## 5. Leakage Controls
All sets enforce strict graph isolation. No edges traverse between train, validation, or test sets. No chronological event splitting is used.

## 6. Target Reporting Metrics
- **Track A**: 12-Class Validation & Test Macro-F1 (computed only over the 12 supervised classes).
- **Track B**: Zero-Shot Technique Test Accuracy, specifically measuring prediction distribution on the 10,000 completely unseen T1018 events.
"""
with open(os.path.join(OUT_DIR, "recommended_protocol.md"), "w") as f:
    f.write(recommended)
    
print("Split design V2 generated successfully.")
