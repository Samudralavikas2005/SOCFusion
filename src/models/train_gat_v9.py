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
from torch.utils.data import WeightedRandomSampler

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.losses import FocalLoss

class SOCFusionGATv9(nn.Module):
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
        
        self.edge_types = edge_types
        if edge_types:
            convs1 = {e: GATv2Conv(hidden_dim, hidden_dim//heads, heads=heads, add_self_loops=False) for e in edge_types}
            self.conv1 = HeteroConv(convs1, aggr='mean')
            
            convs2 = {e: GATv2Conv(hidden_dim, hidden_dim//heads, heads=heads, add_self_loops=False) for e in edge_types}
            self.conv2 = HeteroConv(convs2, aggr='mean')
        else:
            self.conv1 = None
            self.conv2 = None
            
        self.classifier = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x_dict, edge_index_dict):
        h_dict = {}
        h_dict['Event'] = self.event_proj(x_dict['Event'])
        
        if 'Process' in x_dict: h_dict['Process'] = torch.zeros((x_dict['Process'].shape[0], h_dict['Event'].shape[1]), device=h_dict['Event'].device)
        
        if self.conv1 is not None:
            filtered_edge_index = {k: v for k, v in edge_index_dict.items() if k in self.edge_types}
            h_out = self.conv1(h_dict, filtered_edge_index)
            if 'Event' in h_out:
                h_dict['Event'] = h_dict['Event'] + F.relu(h_out['Event'])
                
            h_out2 = self.conv2(h_dict, filtered_edge_index)
            if 'Event' in h_out2:
                h_dict['Event'] = h_dict['Event'] + F.relu(h_out2['Event'])
                
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
    
    if 'Process' in nodes:
        data['Process'].num_nodes = nodes['Process'].get('num_nodes', 0)
        data['Process'].x = torch.empty((data['Process'].num_nodes, 0))
    else:
        data['Process'].num_nodes = 0
        data['Process'].x = torch.empty((0, 0))
    
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
    
    criterion = nn.CrossEntropyLoss(weight=alpha).to(device)
        
    in_channels = train_data['Event'].x.size(1)
    
    edge_types = [
        ('Event', 'INVOLVES', 'Process'),
        ('Process', 'SPAWNED', 'Process'),
        ('Process', 'rev_INVOLVES', 'Event')
    ]
        
    torch.manual_seed(42)
    model = SOCFusionGATv9(in_channels=in_channels, hidden_dim=config['hidden_dim'], 
                           num_classes=12, edge_types=edge_types, 
                           heads=config['heads'], dropout=config['dropout']).to(device)
                           
    optimizer = optim.AdamW(model.parameters(), lr=config['lr'], weight_decay=config['weight_decay'])
    
    best_val_f1 = -1
    best_val_acc = -1
    best_val_bal_acc = -1
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
            val_acc = accuracy_score(y_val_true, y_val_pred)
            val_bal_acc = balanced_accuracy_score(y_val_true, y_val_pred)
            
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_val_acc = val_acc
            best_val_bal_acc = val_bal_acc
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
        test_acc = accuracy_score(y_test_true, y_test_pred)
        
    return best_val_f1, best_val_acc, best_val_bal_acc, test_macro_f1, test_acc, test_bal_acc, best_model_path, y_test_pred, y_test_true

def main():
    OUT_DIR = "data/processed/gat_v9"
    ANALYSIS_DIR = "data/analysis/synthetic_host_v1"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_data = load_graph("data/processed/graphs_synthetic_v1/train_data.pt").to(device)
    val_data = load_graph("data/processed/graphs_synthetic_v1/val_data.pt").to(device)
    test_data = load_graph("data/processed/graphs_synthetic_v1/test_data.pt").to(device)
    
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    track_a_mapped.sort()
    
    config = {'hidden_dim': 128, 'heads': 4, 'dropout': 0.3, 'lr': 1e-3, 'weight_decay': 1e-4, 'loss': 'Weighted CE'}
    
    print(f"\n--- Training GAT V9 (Synthetic Augmented) ---")
    val_f1, val_acc, val_bal_acc, test_f1, test_acc, test_bal_acc, model_path, y_pred, y_true = train_eval(
        train_data, val_data, test_data, track_a_mapped, config, device, OUT_DIR
    )
    
    print(f"Val F1: {val_f1:.4f} | Val Acc: {val_acc:.4f} | Test F1: {test_f1:.4f} | Test Acc: {test_acc:.4f}")
    
    results = [{
        'model': 'GAT V9 Synthetic Augmented',
        'val_f1': val_f1,
        'val_acc': val_acc,
        'val_bal_acc': val_bal_acc,
        'test_f1': test_f1,
        'test_acc': test_acc,
        'test_bal_acc': test_bal_acc
    }]
    
    pd.DataFrame(results).to_csv(os.path.join(ANALYSIS_DIR, "gat_v9_results.csv"), index=False)
    
    test_macro_f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
    test_weighted_f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    test_acc = accuracy_score(y_true, y_pred)
    test_bal_acc = balanced_accuracy_score(y_true, y_pred)
    test_macro_recall = recall_score(y_true, y_pred, average='macro', zero_division=0)
    
    # Baseline GAT V6 scores 
    # v6_test_acc = 0.0240, v6_test_f1 = 0.1052
    
    report = f"""# GAT V6 vs GAT V9 (Synthetic Augmentation) Comparison

| Metric | GAT V6 | GAT V9 |
|--------|--------|--------|
| Accuracy | 2.40% | {test_acc*100:.2f}% |
| Macro-F1 | 10.52% | {test_macro_f1*100:.2f}% |
| Balanced Accuracy | Unknown | {test_bal_acc*100:.2f}% |
| Macro Recall | Unknown | {test_macro_recall*100:.2f}% |

## Conclusion
If GAT V9 (Synthetic) does not substantially improve upon the V6 baseline on the REAL TEST SET, then synthetic replication of existing techniques to new IP/Host environments does not solve the fundamental domain generalization bottleneck. 
"""
    with open(os.path.join(ANALYSIS_DIR, "v6_vs_v9_comparison.md"), "w") as f:
        f.write(report)
        
    print("Experiments and reports generated.")

if __name__ == "__main__":
    main()
