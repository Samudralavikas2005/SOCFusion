import os
import json
import torch
from torch_geometric.data import HeteroData
import numpy as np
import pickle
import csv
import sys
from sklearn.metrics import confusion_matrix
import torch.nn.functional as F

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.gat import SOCFusionGAT

def load_graph(filepath):
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
        
    data = HeteroData()
    nodes = data_dict['nodes']
    
    data['Event'].x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    data['Event'].y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    data['Event'].num_nodes = nodes['Event']['num_nodes']
    
    data['Host'].num_nodes = nodes['Host']['num_nodes']
    data['Host'].x = torch.empty((nodes['Host']['num_nodes'], 0))
    
    data['User'].num_nodes = nodes['User']['num_nodes']
    data['User'].x = torch.empty((nodes['User']['num_nodes'], 0))
    
    data['Process'].num_nodes = nodes['Process']['num_nodes']
    data['Process'].x = torch.empty((nodes['Process']['num_nodes'], 0))
    
    for edge_type, edge_data in data_dict['edges'].items():
        if len(edge_data['edge_index'][0]) > 0:
            data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
        else:
            data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
            
    import torch_geometric.transforms as T
    data = T.ToUndirected()(data)
    return data

def main():
    OUT_DIR = "data/analysis/gat_v2_diagnostic"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    train_data = load_graph("data/processed/graphs_v2/train_data.pt")
    val_data = load_graph("data/processed/graphs_v2/val_data.pt")
    test_data = load_graph("data/processed/graphs_v2/test_data.pt")
    
    # 1. Entity Embedding Audit
    audit_data = []
    entities = ['Host', 'User', 'Process']
    for ent in entities:
        audit_data.append({
            'Entity': ent,
            'Train_Nodes': train_data[ent].num_nodes,
            'Val_Nodes': val_data[ent].num_nodes,
            'Test_Nodes': test_data[ent].num_nodes
        })
        
    with open(os.path.join(OUT_DIR, "entity_embedding_audit.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['Entity', 'Train_Nodes', 'Val_Nodes', 'Test_Nodes'])
        writer.writeheader()
        writer.writerows(audit_data)
        
    # Load Model
    with open("data/analysis/gat_v2/training_config.json", "r") as f:
        config = json.load(f)
        
    model = SOCFusionGAT(
        hidden_dim=config["hidden_dim"], 
        num_heads=config["num_heads"], 
        num_classes=config["num_classes"], 
        edge_types=[tuple(e) for e in train_data.edge_types],
        num_hosts=train_data['Host'].num_nodes,
        num_users=train_data['User'].num_nodes,
        num_processes=train_data['Process'].num_nodes
    )
    
    model.load_state_dict(torch.load("data/processed/gat_v2/checkpoints/best_model.pth", map_location='cpu'))
    model.eval()

    # Get Predictions
    track_b = torch.tensor(config["track_b_classes"])
    track_a = config["track_a_classes"]
    
    distributions = []
    class_dist = []
    
    for split_name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        with torch.no_grad():
            try:
                out, _ = model(data.x_dict, data.edge_index_dict)
            except Exception as e:
                print(f"Error evaluating {split_name}: {e}")
                # We need to mock this for test if it fails due to embedding size mismatch
                # Wait, if test_data nodes < train_data nodes, it won't crash, it will just reuse indices 0..N-1
                out = torch.zeros(data['Event'].num_nodes, config["num_classes"]) # Dummy
        
        y = data['Event'].y
        mask = ~torch.isin(y, track_b)
        
        # Distributions for Track A
        y_a = y[mask]
        
        y_counts = torch.bincount(y_a, minlength=15)
        for c in range(15):
            if c in track_a:
                class_dist.append({
                    "split": split_name,
                    "class_idx": c,
                    "true_count": y_counts[c].item()
                })
        
        if out.sum() != 0:
            pred = out.argmax(dim=-1)
            pred_a = pred[mask]
            pred_counts = torch.bincount(pred_a, minlength=15)
            for c in range(15):
                if c in track_a:
                    distributions.append({
                        "split": split_name,
                        "class_idx": c,
                        "pred_count": pred_counts[c].item()
                    })

    with open(os.path.join(OUT_DIR, "class_distribution.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['split', 'class_idx', 'true_count'])
        writer.writeheader()
        writer.writerows(class_dist)
        
    with open(os.path.join(OUT_DIR, "prediction_distribution.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['split', 'class_idx', 'pred_count'])
        writer.writeheader()
        writer.writerows(distributions)
        
    # Analyze Feature Signal
    # Let's check the variance of the 17 event features
    feat_var = train_data['Event'].x.var(dim=0).numpy()
    feat_mean = train_data['Event'].x.mean(dim=0).numpy()
    
    with open(os.path.join(OUT_DIR, "feature_signal_analysis.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["feature_idx", "mean", "variance"])
        for i in range(17):
            writer.writerow([i, feat_mean[i], feat_var[i]])
            
    # Message Passing Analysis
    # Let's check how many edges actually exist for message passing in test
    mp_analysis = []
    for split_name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        for edge_type in data.edge_types:
            mp_analysis.append({
                "split": split_name,
                "edge_type": "-".join(edge_type),
                "edge_count": data[edge_type].edge_index.size(1)
            })
            
    with open(os.path.join(OUT_DIR, "graph_message_passing_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['split', 'edge_type', 'edge_count'])
        writer.writeheader()
        writer.writerows(mp_analysis)
        
    # Confusion Matrix Analysis
    # Analyze the saved test confusion matrix
    cm = np.loadtxt("data/analysis/gat_v2/confusion_matrix.csv", delimiter=",", dtype=int)
    cm_analysis = []
    for i, true_idx in enumerate(track_a):
        for j, pred_idx in enumerate(track_a):
            if cm[i, j] > 0:
                cm_analysis.append({
                    "true_class": true_idx,
                    "pred_class": pred_idx,
                    "count": cm[i, j]
                })
                
    with open(os.path.join(OUT_DIR, "confusion_matrix_analysis.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['true_class', 'pred_class', 'count'])
        writer.writeheader()
        writer.writerows(cm_analysis)
        
    print("Diagnostic extraction complete.")

if __name__ == "__main__":
    main()
