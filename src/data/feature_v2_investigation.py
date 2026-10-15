import os
import torch
import numpy as np
import pickle
import csv
import sys
import collections

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "day_of_week_sin", "day_of_week_cos", "log_type_idx",
    "event_code_idx", "source_idx", "process_name_idx", "is_lolbin", "msg_length",
    "ps_token_count", "cmd_length", "cmd_entropy", "ps_b64_indicator",
    "has_process_id", "has_user", "has_command_line"
]

def load_event_data(filepath):
    print(f"Loading {filepath}...")
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
    nodes = data_dict['nodes']
    x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    return x, y

def compute_stats(x):
    if x.shape[0] == 0:
        return [0]*17, [0]*17, [0]*17, [0]*17
    means = x.mean(dim=0).tolist()
    stds = x.std(dim=0).tolist()
    mins = x.min(dim=0)[0].tolist()
    maxs = x.max(dim=0)[0].tolist()
    return means, stds, mins, maxs

def main():
    OUT_DIR = "data/analysis/feature_engineering_v2_design"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    x_train, y_train = load_event_data("data/processed/graphs_v2/train_data.pt")
    x_val, y_val = load_event_data("data/processed/graphs_v2/val_data.pt")
    x_test, y_test = load_event_data("data/processed/graphs_v2/test_data.pt")
    
    track_a_classes = [0, 1, 2, 4, 5, 6, 7, 10, 11, 12, 13, 14]
    
    # 2. Audit All Features & 4. Distribution Shift
    print("Computing global distributions...")
    dist_shift_rows = []
    t_mean, t_std, t_min, t_max = compute_stats(x_train)
    v_mean, v_std, v_min, v_max = compute_stats(x_val)
    te_mean, te_std, te_min, te_max = compute_stats(x_test)
    
    for i, fname in enumerate(FEATURE_NAMES):
        shift_train_val = abs(t_mean[i] - v_mean[i])
        shift_train_test = abs(t_mean[i] - te_mean[i])
        # normalize shift by train std if possible
        norm_shift = shift_train_test / (t_std[i] + 1e-6)
        
        dist_shift_rows.append({
            "feature": fname,
            "train_mean": t_mean[i], "train_std": t_std[i],
            "val_mean": v_mean[i], "val_std": v_std[i],
            "test_mean": te_mean[i], "test_std": te_std[i],
            "shift_train_test_abs": shift_train_test,
            "shift_train_test_normalized": norm_shift
        })
        
    dist_shift_rows.sort(key=lambda x: x["shift_train_test_normalized"], reverse=True)
    
    with open(os.path.join(OUT_DIR, "feature_distribution_shift.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=dist_shift_rows[0].keys())
        writer.writeheader()
        writer.writerows(dist_shift_rows)
        
    stability_rows = [{"rank": idx+1, "feature": row["feature"], "normalized_shift": row["shift_train_test_normalized"]} for idx, row in enumerate(reversed(dist_shift_rows))]
    with open(os.path.join(OUT_DIR, "feature_stability_ranking.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rank", "feature", "normalized_shift"])
        writer.writeheader()
        writer.writerows(stability_rows)

    # 5. Class-Conditional Generalization
    print("Computing class-conditional distributions...")
    class_part_rows = []
    for c in track_a_classes:
        c_train = x_train[y_train == c]
        c_test = x_test[y_test == c]
        
        if c_train.shape[0] == 0 or c_test.shape[0] == 0:
            continue
            
        ct_mean, _, _, _ = compute_stats(c_train)
        cte_mean, _, _, _ = compute_stats(c_test)
        
        for i, fname in enumerate(FEATURE_NAMES):
            diff = abs(ct_mean[i] - cte_mean[i])
            class_part_rows.append({
                "class_idx": c,
                "feature": fname,
                "train_mean": ct_mean[i],
                "test_mean": cte_mean[i],
                "abs_diff": diff
            })
            
    with open(os.path.join(OUT_DIR, "feature_class_partition_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["class_idx", "feature", "train_mean", "test_mean", "abs_diff"])
        writer.writeheader()
        writer.writerows(class_part_rows)
        
    # 3. Environment Dependence & Categorical Analysis
    print("Generating environment/categorical analysis...")
    env_rows = [
        {"feature": "log_type_idx", "dependence": "High", "reason": "Categorical index assigned based on training data ordering"},
        {"feature": "event_code_idx", "dependence": "High", "reason": "Categorical index assigned based on training data ordering"},
        {"feature": "source_idx", "dependence": "High", "reason": "Categorical index assigned based on training data ordering"},
        {"feature": "process_name_idx", "dependence": "Very High", "reason": "Highly volatile string index, unique across hosts"},
        {"feature": "hour_sin", "dependence": "Low", "reason": "Universal cyclical time"},
        {"feature": "msg_length", "dependence": "Medium", "reason": "Can vary based on host-specific paths embedded in messages"},
        {"feature": "cmd_length", "dependence": "Medium", "reason": "Can vary based on username/hostname in command paths"},
        {"feature": "is_lolbin", "dependence": "Low", "reason": "Universal binary names"}
    ]
    with open(os.path.join(OUT_DIR, "feature_environment_dependence.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["feature", "dependence", "reason"])
        writer.writeheader()
        writer.writerows(env_rows)
        
    cat_rows = [
        {"feature": "log_type_idx", "issue": "Treated as continuous integer"},
        {"feature": "event_code_idx", "issue": "Treated as continuous integer"},
        {"feature": "source_idx", "issue": "Treated as continuous integer"},
        {"feature": "process_name_idx", "issue": "Treated as continuous integer, large unbounded vocabulary"}
    ]
    with open(os.path.join(OUT_DIR, "categorical_feature_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["feature", "issue"])
        writer.writeheader()
        writer.writerows(cat_rows)

    # Candidate Features, Leakage, Normalization, Schema
    candidates = [
        {"name": "event_code_ohe", "category": "Event", "desc": "One-hot encoding of common event codes (e.g., 4688, 4104)"},
        {"name": "log_type_ohe", "category": "Event", "desc": "One-hot encoding of known log types"},
        {"name": "cmd_length_norm", "category": "Command", "desc": "Command length normalized by training population mean/std"},
        {"name": "ps_token_count_norm", "category": "PowerShell", "desc": "Token count normalized"},
        {"name": "cmd_entropy", "category": "Command", "desc": "Keep as-is, inherently normalized (0-8)"},
        {"name": "is_lolbin", "category": "Command", "desc": "Keep as-is, binary indicator"},
        {"name": "time_since_prev_event", "category": "Temporal", "desc": "Time delta to previous event on same host (log-scaled)"},
    ]
    with open(os.path.join(OUT_DIR, "candidate_features.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "category", "desc"])
        writer.writeheader()
        writer.writerows(candidates)
        
    leakage = [
        {"name": "event_code_ohe", "leakage_risk": "None if limited to fixed universal vocab"},
        {"name": "time_since_prev_event", "leakage_risk": "None if causal (computed from sorted timestamps)"},
    ]
    with open(os.path.join(OUT_DIR, "candidate_feature_leakage.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "leakage_risk"])
        writer.writeheader()
        writer.writerows(leakage)

    norm = [
        {"feature": "cmd_length", "strategy": "Global training mean/std normalization"},
        {"feature": "msg_length", "strategy": "Global training mean/std normalization"},
        {"feature": "time_since_prev_event", "strategy": "Log transform + Global normalization"}
    ]
    with open(os.path.join(OUT_DIR, "normalization_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["feature", "strategy"])
        writer.writeheader()
        writer.writerows(norm)

    schema = [
        {"name": "event_code_ohe", "status": "CORE", "action": "TRANSFORM", "source": "event_code_idx"},
        {"name": "process_name_idx", "status": "REMOVE", "action": "REMOVE", "source": "process_name_idx"},
        {"name": "cmd_entropy", "status": "CORE", "action": "KEEP", "source": "cmd_entropy"},
    ]
    with open(os.path.join(OUT_DIR, "feature_v2_schema.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "status", "action", "source"])
        writer.writeheader()
        writer.writerows(schema)

    print("Investigation complete.")

if __name__ == "__main__":
    main()
