import os
import json
import torch
from torch_geometric.data import HeteroData
import numpy as np
import pickle
import csv
import sys
import collections
from sklearn.metrics import confusion_matrix
import math

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

FEATURE_NAMES = [
    "hour_sin", "hour_cos", "day_of_week_sin", "day_of_week_cos", "log_type_idx",
    "event_code_idx", "source_idx", "process_name_idx", "is_lolbin", "msg_length",
    "ps_token_count", "cmd_length", "cmd_entropy", "ps_b64_indicator",
    "has_process_id", "has_user", "has_command_line"
]

def load_graph(filepath):
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
        
    data = HeteroData()
    nodes = data_dict['nodes']
    
    data['Event'].x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    data['Event'].y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    data['Event'].num_nodes = nodes['Event']['num_nodes']
    
    data['Host'].num_nodes = nodes['Host']['num_nodes']
    data['User'].num_nodes = nodes['User']['num_nodes']
    data['Process'].num_nodes = nodes['Process']['num_nodes']
    
    for edge_type, edge_data in data_dict['edges'].items():
        if len(edge_data['edge_index'][0]) > 0:
            data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
        else:
            data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
            
    return data

def main():
    OUT_DIR = "data/analysis/gat_v3_signal_audit"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    print("Loading graphs...")
    train_data = load_graph("data/processed/graphs_v2/train_data.pt")
    val_data = load_graph("data/processed/graphs_v2/val_data.pt")
    test_data = load_graph("data/processed/graphs_v2/test_data.pt")
    
    with open("data/analysis/gat_v3/training_config.json", "r") as f:
        config = json.load(f)
        
    track_a = config["track_a_classes"]
    track_b = config["track_b_classes"]
    track_a_tensor = torch.tensor(track_a)
    
    # 1. Feature Signal Audit
    print("Running Feature Signal Audit...")
    x = train_data['Event'].x
    y = train_data['Event'].y
    
    mask_a = torch.isin(y, track_a_tensor)
    x_a = x[mask_a]
    y_a = y[mask_a]
    
    feature_stats = []
    for i in range(17):
        col = x[:, i]
        unique_vals = torch.unique(col)
        zeros = (col == 0).sum().item()
        feature_stats.append({
            "feature": FEATURE_NAMES[i],
            "unique_values": len(unique_vals),
            "zero_missing_count": zeros,
            "zero_prevalence_pct": zeros / len(col) * 100,
            "mean": col.mean().item(),
            "variance": col.var().item(),
            "min": col.min().item(),
            "max": col.max().item()
        })
        
    with open(os.path.join(OUT_DIR, "feature_statistics.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=feature_stats[0].keys())
        writer.writeheader()
        writer.writerows(feature_stats)
        
    # Feature Class Separability
    sep_data = []
    for c in track_a:
        c_mask = (y_a == c)
        if c_mask.sum() == 0:
            continue
        c_x = x_a[c_mask]
        means = c_x.mean(dim=0).tolist()
        row = {"class": c}
        for i in range(17):
            row[FEATURE_NAMES[i]] = means[i]
        sep_data.append(row)
        
    with open(os.path.join(OUT_DIR, "feature_class_separability.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["class"] + FEATURE_NAMES)
        writer.writeheader()
        writer.writerows(sep_data)
        
    # 2. Duplicate / Feature Collision Analysis
    print("Running Feature Collision Analysis...")
    # Convert tensor rows to tuples to find exact duplicates
    x_list = x_a.tolist()
    y_list = y_a.tolist()
    
    feature_to_classes = collections.defaultdict(set)
    feature_counts = collections.defaultdict(int)
    
    for i in range(len(x_list)):
        feat_tuple = tuple(x_list[i])
        feature_to_classes[feat_tuple].add(y_list[i])
        feature_counts[feat_tuple] += 1
        
    exact_duplicates = sum(count - 1 for count in feature_counts.values() if count > 1)
    collisions = {k: v for k, v in feature_to_classes.items() if len(v) > 1}
    collision_events = sum(feature_counts[k] for k in collisions.keys())
    
    with open(os.path.join(OUT_DIR, "feature_collision_analysis.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_track_a_events", len(x_list)])
        writer.writerow(["unique_feature_vectors", len(feature_counts)])
        writer.writerow(["exact_feature_duplicates", exact_duplicates])
        writer.writerow(["vectors_with_multiple_classes", len(collisions)])
        writer.writerow(["events_involved_in_collisions", collision_events])
        writer.writerow(["collision_event_pct", collision_events / len(x_list) * 100])
        
    # 3. Graph Message Passing Analysis
    print("Running Edge Type Analysis...")
    edge_stats = []
    for edge_type in train_data.edge_types:
        e_name = "-".join(edge_type)
        edge_index = train_data[edge_type].edge_index
        num_edges = edge_index.size(1)
        src_nodes = len(torch.unique(edge_index[0])) if num_edges > 0 else 0
        dst_nodes = len(torch.unique(edge_index[1])) if num_edges > 0 else 0
        edge_stats.append({
            "edge_type": e_name,
            "total_edges": num_edges,
            "unique_src_nodes": src_nodes,
            "unique_dst_nodes": dst_nodes,
            "avg_degree_dst": (num_edges / dst_nodes) if dst_nodes > 0 else 0
        })
        
    with open(os.path.join(OUT_DIR, "edge_type_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=edge_stats[0].keys())
        writer.writeheader()
        writer.writerows(edge_stats)
        
    # 4. Temporal Edge Analysis (PRECEDES)
    print("Running Temporal Edge Analysis...")
    temp_stats = {}
    if ('Event', 'PRECEDES', 'Event') in train_data.edge_types:
        edge_index = train_data['Event', 'PRECEDES', 'Event'].edge_index
        src, dst = edge_index[0], edge_index[1]
        src_y = y[src]
        dst_y = y[dst]
        
        same_class = (src_y == dst_y).sum().item()
        diff_class = len(src_y) - same_class
        
        temp_stats["total_precedes"] = len(src_y)
        temp_stats["same_class_edges"] = same_class
        temp_stats["diff_class_edges"] = diff_class
        temp_stats["same_class_pct"] = same_class / len(src_y) * 100 if len(src_y) > 0 else 0
    
    with open(os.path.join(OUT_DIR, "temporal_edge_analysis.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for k, v in temp_stats.items():
            writer.writerow([k, v])
            
    # 5. Class Distribution Audit
    print("Running Class Distribution Audit...")
    cd_data = []
    for split_name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        split_y = data['Event'].y
        mask = torch.isin(split_y, track_a_tensor)
        split_y_a = split_y[mask]
        counts = torch.bincount(split_y_a, minlength=15)
        
        for c in track_a:
            cd_data.append({
                "split": split_name,
                "class_idx": c,
                "count": counts[c].item(),
                "percentage": counts[c].item() / len(split_y_a) * 100 if len(split_y_a) > 0 else 0
            })
            
    with open(os.path.join(OUT_DIR, "class_distribution.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["split", "class_idx", "count", "percentage"])
        writer.writeheader()
        writer.writerows(cd_data)
        
    # 6. Prediction Collapse Audit
    print("Running Prediction Collapse Audit...")
    pred_data = []
    try:
        # Load test confusion matrix
        cm = np.loadtxt("data/analysis/gat_v3/confusion_matrix.csv", delimiter=",")
        for i, true_c in enumerate(track_a):
            for j, pred_c in enumerate(track_a):
                if cm[i, j] > 0:
                    pred_data.append({
                        "true_class": true_c,
                        "pred_class": pred_c,
                        "count": int(cm[i, j])
                    })
    except Exception as e:
        print(f"Error loading CM: {e}")
        
    with open(os.path.join(OUT_DIR, "prediction_distribution.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["true_class", "pred_class", "count"])
        writer.writeheader()
        writer.writerows(pred_data)
        
    # 7. Loss/Class-Weight Audit
    print("Running Loss Weight Audit...")
    weight_data = []
    try:
        with open("data/analysis/gat_v3/class_weights.csv", "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                weight_data.append(row)
    except:
        pass
        
    with open(os.path.join(OUT_DIR, "loss_weight_audit.csv"), "w", newline="") as f:
        if weight_data:
            writer = csv.DictWriter(f, fieldnames=["class_idx", "weight"])
            writer.writeheader()
            writer.writerows(weight_data)
            
    # 8. Embedding Signal Audit
    print("Running Embedding Signal Audit...")
    try:
        train_emb = torch.load("data/processed/gat_v3/embeddings/train_embeddings.pt", map_location='cpu')
        train_emb_a = train_emb[mask_a]
        
        centroids = {}
        for c in track_a:
            c_mask = (y_a == c)
            if c_mask.sum() > 0:
                centroids[c] = train_emb_a[c_mask].mean(dim=0)
                
        emb_stats = []
        for c in track_a:
            if c not in centroids: continue
            c_mask = (y_a == c)
            # average L2 distance to own centroid
            own_dist = torch.norm(train_emb_a[c_mask] - centroids[c], dim=1).mean().item()
            
            # distance to nearest other centroid
            min_other_dist = float('inf')
            for other_c, other_cent in centroids.items():
                if c != other_c:
                    dist = torch.norm(centroids[c] - other_cent).item()
                    if dist < min_other_dist:
                        min_other_dist = dist
                        
            emb_stats.append({
                "class_idx": c,
                "avg_dist_to_centroid": own_dist,
                "dist_to_nearest_other_centroid": min_other_dist,
                "ratio": own_dist / min_other_dist if min_other_dist > 0 else float('inf')
            })
            
        with open(os.path.join(OUT_DIR, "embedding_signal_analysis.csv"), "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["class_idx", "avg_dist_to_centroid", "dist_to_nearest_other_centroid", "ratio"])
            writer.writeheader()
            writer.writerows(emb_stats)
    except Exception as e:
        print(f"Error loading embeddings: {e}")

    print("Signal audit complete.")

if __name__ == "__main__":
    main()
