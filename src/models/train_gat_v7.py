import os
import json
import pickle
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T
from torch_geometric.nn import HeteroConv, GATv2Conv
import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score, confusion_matrix, balanced_accuracy_score
import time
import argparse
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.losses import FocalLoss

class SOCFusionGATv7(nn.Module):
    def __init__(self, in_channels, hidden_dim, num_classes, edge_types, heads=4, dropout=0.3):
        super().__init__()
        self.event_proj = nn.Sequential(
            nn.Linear(in_channels, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        
        self.host_emb = nn.Parameter(torch.randn(1, hidden_dim))
        self.user_emb = nn.Parameter(torch.randn(1, hidden_dim))
        self.process_emb = nn.Parameter(torch.randn(1, hidden_dim))
        
        self.edge_types = edge_types
        if edge_types:
            convs1 = {e: GATv2Conv(hidden_dim, hidden_dim//heads, heads=heads, add_self_loops=False) for e in edge_types}
            self.conv1 = HeteroConv(convs1, aggr='mean')
        else:
            self.conv1 = None
            
        self.classifier = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x_dict, edge_index_dict):
        h_dict = {}
        h_dict['Event'] = self.event_proj(x_dict['Event'])
        
        if 'Host' in x_dict: h_dict['Host'] = self.host_emb.expand(x_dict['Host'].shape[0], -1)
        if 'User' in x_dict: h_dict['User'] = self.user_emb.expand(x_dict['User'].shape[0], -1)
        if 'Process' in x_dict: h_dict['Process'] = self.process_emb.expand(x_dict['Process'].shape[0], -1)
        
        if self.conv1 is not None:
            filtered_edge_index = {k: v for k, v in edge_index_dict.items() if k in self.edge_types}
            h_out = self.conv1(h_dict, filtered_edge_index)
            if 'Event' in h_out:
                h_dict['Event'] = h_dict['Event'] + F.relu(h_out['Event'])
                
        return self.classifier(h_dict['Event'])

def load_graph(filepath):
    print(f"Loading {filepath}...")
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
        
    data = HeteroData()
    nodes = data_dict['nodes']
    data['Event'].x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    data['Event'].y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    data['Event'].num_nodes = nodes['Event']['num_nodes']
    data['Host'].num_nodes = nodes['Host'].get('num_nodes', 0)
    data['Host'].x = torch.empty((data['Host'].num_nodes, 0))
    data['User'].num_nodes = nodes['User'].get('num_nodes', 0)
    data['User'].x = torch.empty((data['User'].num_nodes, 0))
    data['Process'].num_nodes = nodes['Process'].get('num_nodes', 0)
    data['Process'].x = torch.empty((data['Process'].num_nodes, 0))
    
    for edge_type, edge_data in data_dict['edges'].items():
        if len(edge_data['edge_index'][0]) > 0:
            data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
        else:
            data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
            
    data = T.ToUndirected()(data)
    return data

def train_eval(train_data, val_data, test_data, track_a_mapped, config, device, out_dir):
    a_to_idx = {orig: i for i, orig in enumerate(track_a_mapped)}
    
    def map_labels(data):
        mask = torch.isin(data['Event'].y, torch.tensor(track_a_mapped, device=device))
        mapped_y = data['Event'].y.clone()
        for orig, new_idx in a_to_idx.items():
            mapped_y[data['Event'].y == orig] = new_idx
        return mask, mapped_y
        
    train_mask, train_y = map_labels(train_data)
    val_mask, val_y = map_labels(val_data)
    test_mask, test_y = map_labels(test_data)
    
    class_counts = torch.bincount(train_y[train_mask], minlength=12).float()
    alpha = torch.zeros(12, device=device)
    present = class_counts > 0
    alpha[present] = 1.0 / class_counts[present]
    alpha = alpha / alpha.sum() * present.sum()
    
    in_channels = train_data['Event'].x.size(1)
    
    edge_types = [
        ('Event', 'INVOLVES', 'Process'),
        ('Process', 'SPAWNED', 'Process'),
        ('Process', 'rev_INVOLVES', 'Event')
    ]
    
    torch.manual_seed(42)
    model = SOCFusionGATv7(in_channels=in_channels, hidden_dim=config['hidden_dim'], 
                           num_classes=12, edge_types=edge_types, 
                           heads=config['heads'], dropout=config['dropout']).to(device)
                           
    criterion = FocalLoss(alpha=alpha.cpu(), gamma=2.0).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=config['lr'], weight_decay=config['weight_decay'])
    
    best_val_f1 = -1
    patience = 15
    patience_counter = 0
    
    os.makedirs(os.path.join(out_dir, "checkpoints"), exist_ok=True)
    best_model_path = os.path.join(out_dir, "checkpoints", f"best_model_run.pth")
    
    for epoch in range(100):
        model.train()
        optimizer.zero_grad()
        out = model(train_data.x_dict, train_data.edge_index_dict)
        loss = criterion(out[train_mask], train_y[train_mask])
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            val_out = model(val_data.x_dict, val_data.edge_index_dict)
            val_loss = criterion(val_out[val_mask], val_y[val_mask]).item()
            y_val_pred = val_out[val_mask].argmax(dim=-1).cpu().numpy()
            y_val_true = val_y[val_mask].cpu().numpy()
            val_f1 = f1_score(y_val_true, y_val_pred, average='macro', zero_division=0)
            
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            patience_counter = 0
            torch.save(model.state_dict(), best_model_path)
        else:
            patience_counter += 1
            if patience_counter >= patience:
                break
                
    model.load_state_dict(torch.load(best_model_path))
    model.eval()
    with torch.no_grad():
        test_out = model(test_data.x_dict, test_data.edge_index_dict)
        y_test_pred = test_out[test_mask].argmax(dim=-1).cpu().numpy()
        y_test_true = test_y[test_mask].cpu().numpy()
        
        test_macro_f1 = f1_score(y_test_true, y_test_pred, average='macro', zero_division=0)
        test_bal_acc = balanced_accuracy_score(y_test_true, y_test_pred)
        
    return best_val_f1, test_macro_f1, test_bal_acc, best_model_path, y_test_pred, y_test_true

def main():
    OUT_DIR = "data/processed/gat_v7"
    ANALYSIS_DIR = "data/analysis/gat_v7"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_data = load_graph("data/processed/graphs_v5/train_data.pt").to(device)
    val_data = load_graph("data/processed/graphs_v5/val_data.pt").to(device)
    test_data = load_graph("data/processed/graphs_v5/test_data.pt").to(device)
    
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    track_a_mapped.sort()
    
    grid = [
        {'hidden_dim': 128, 'heads': 4, 'dropout': 0.3, 'lr': 1e-3, 'weight_decay': 1e-4},
        {'hidden_dim': 256, 'heads': 4, 'dropout': 0.3, 'lr': 1e-3, 'weight_decay': 1e-4},
        {'hidden_dim': 128, 'heads': 8, 'dropout': 0.1, 'lr': 1e-3, 'weight_decay': 1e-5}
    ]
    
    best_config_f1 = -1
    best_config = None
    best_model_path_overall = None
    best_y_pred = None
    best_y_true = None
    
    results = []
    
    for idx, config in enumerate(grid):
        print(f"\n--- Testing Config {idx+1}/{len(grid)} ---")
        print(config)
        val_f1, test_f1, test_bal_acc, model_path, y_pred, y_true = train_eval(
            train_data, val_data, test_data, track_a_mapped, config, device, OUT_DIR
        )
        print(f"Val F1: {val_f1:.4f} | Test F1: {test_f1:.4f} | Test Bal Acc: {test_bal_acc:.4f}")
        
        config['val_f1'] = val_f1
        config['test_f1'] = test_f1
        config['test_bal_acc'] = test_bal_acc
        results.append(config)
        
        if val_f1 > best_config_f1:
            best_config_f1 = val_f1
            best_config = config
            best_model_path_overall = model_path
            best_y_pred = y_pred
            best_y_true = y_true
            
    print(f"\nBest Config selected on Val F1: {best_config}")
    
    # Save best model to final
    import shutil
    shutil.copy(best_model_path_overall, os.path.join(OUT_DIR, "best_model.pth"))
    
    # Evaluate
    test_f1 = f1_score(best_y_true, best_y_pred, average='macro', zero_division=0)
    test_wf1 = f1_score(best_y_true, best_y_pred, average='weighted', zero_division=0)
    test_acc = accuracy_score(best_y_true, best_y_pred)
    test_bal_acc = balanced_accuracy_score(best_y_true, best_y_pred)
    
    precision = precision_score(best_y_true, best_y_pred, average=None, zero_division=0)
    recall = recall_score(best_y_true, best_y_pred, average=None, zero_division=0)
    f1 = f1_score(best_y_true, best_y_pred, average=None, zero_division=0)
    
    idx_to_orig = {i: orig for i, orig in enumerate(track_a_mapped)}
    orig_to_str = {v: k for k, v in label_map.items()}
    
    per_class = []
    for i in range(12):
        tech_name = orig_to_str[idx_to_orig[i]]
        per_class.append({
            "technique": tech_name,
            "precision": precision[i],
            "recall": recall[i],
            "f1": f1[i]
        })
        
    cm = confusion_matrix(best_y_true, best_y_pred)
    
    report = f"""# GAT V7 Training Report

## Architecture
- GAT V7 (Process-only structure)
- Feature Schema: V4 (112 dims)
- Edges: INVOLVES, SPAWNED

## Best Hyperparameters
{json.dumps(best_config, indent=4)}

## Overall Performance
- Test Macro-F1: {test_f1:.4f}
- Test Weighted-F1: {test_wf1:.4f}
- Test Balanced Accuracy: {test_bal_acc:.4f}
- Test Accuracy: {test_acc:.4f}

## Per-Class Metrics
"""
    for p in per_class:
        report += f"- **{p['technique']}**: Precision={p['precision']:.4f}, Recall={p['recall']:.4f}, F1={p['f1']:.4f}\n"
        
    with open(os.path.join(ANALYSIS_DIR, "gat_v7_training_report.md"), "w") as f:
        f.write(report)
        
    pd.DataFrame(per_class).to_csv(os.path.join(ANALYSIS_DIR, "per_class_metrics.csv"), index=False)
    np.savetxt(os.path.join(ANALYSIS_DIR, "confusion_matrix.csv"), cm, delimiter=",", fmt="%d")
    pd.DataFrame(results).to_csv(os.path.join(ANALYSIS_DIR, "grid_search_results.csv"), index=False)
    
    comp_report = f"""# Model Comparison

| Model | Test Macro-F1 |
|-------|---------------|
| GAT V3 | 0.0477 |
| Event MLP | 0.0851 |
| GAT V6 (Process-only) | 0.1052 |
| GAT V7 (Process-only, V4) | {test_f1:.4f} |

Conclusion: {"GAT V7 substantially improved performance." if test_f1 > 0.11 else "GAT V7 did NOT substantially improve beyond the inherent graph limits on this highly imbalanced host-isolated dataset."}
"""
    with open(os.path.join(ANALYSIS_DIR, "model_comparison.md"), "w") as f:
        f.write(comp_report)
        
    print("GAT V7 training and evaluation complete.")

if __name__ == "__main__":
    main()
