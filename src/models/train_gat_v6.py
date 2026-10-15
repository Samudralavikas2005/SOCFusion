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
from sklearn.metrics import f1_score, accuracy_score, precision_score, recall_score
import time
import argparse
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.losses import FocalLoss

class SOCFusionGATv6(nn.Module):
    def __init__(self, in_channels, hidden_dim, num_classes, edge_types, dropout=0.3):
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
            # Using mean aggregation to prevent hub explosion
            convs1 = {e: GATv2Conv(hidden_dim, hidden_dim//4, heads=4, add_self_loops=False) for e in edge_types}
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
            # Keep only edges we care about
            filtered_edge_index = {k: v for k, v in edge_index_dict.items() if k in self.edge_types}
            h_out = self.conv1(h_dict, filtered_edge_index)
            if 'Event' in h_out:
                # Residual connection to preserve exact event semantics
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
            
    data = T.ToUndirected()(data)
    return data

def train_eval(config_name, edge_filter_keywords):
    print(f"\n{'='*50}\nStarting Experiment: {config_name}\n{'='*50}")
    
    OUT_DIR = f"data/processed/gat_v6_{config_name}"
    ANALYSIS_DIR = f"data/analysis/gat_v6_{config_name}"
    os.makedirs(os.path.join(OUT_DIR, "checkpoints"), exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_data = load_graph("data/processed/graphs_v4/train_data.pt").to(device)
    val_data = load_graph("data/processed/graphs_v4/val_data.pt").to(device)
    test_data = load_graph("data/processed/graphs_v4/test_data.pt").to(device)
    
    all_edge_types = train_data.edge_types
    # Filter edge types based on keywords
    selected_edges = []
    if edge_filter_keywords:
        for et in all_edge_types:
            if any(k in et[1] for k in edge_filter_keywords):
                selected_edges.append(et)
    print(f"Selected Edges: {selected_edges}")
    
    # Track A filtering
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    track_a_mapped.sort()
    a_to_idx = {orig: i for i, orig in enumerate(track_a_mapped)}
    
    # Map labels to 0-11
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
    model = SOCFusionGATv6(in_channels=in_channels, hidden_dim=128, num_classes=12, edge_types=selected_edges).to(device)
    criterion = FocalLoss(alpha=alpha.cpu(), gamma=2.0).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-4)
    
    best_val_f1 = -1
    patience = 20
    patience_counter = 0
    
    for epoch in range(150):
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
            
        print(f"Epoch {epoch:03d} | Train Loss: {loss.item():.4f} | Val F1: {val_f1:.4f}")
        
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            patience_counter = 0
            torch.save(model.state_dict(), os.path.join(OUT_DIR, "checkpoints", "best_model.pth"))
        else:
            patience_counter += 1
            if patience_counter >= patience:
                print("Early stopping.")
                break
                
    model.load_state_dict(torch.load(os.path.join(OUT_DIR, "checkpoints", "best_model.pth")))
    model.eval()
    with torch.no_grad():
        test_out = model(test_data.x_dict, test_data.edge_index_dict)
        y_test_pred = test_out[test_mask].argmax(dim=-1).cpu().numpy()
        y_test_true = test_y[test_mask].cpu().numpy()
        test_f1 = f1_score(y_test_true, y_test_pred, average='macro', zero_division=0)
        
    print(f"Test Macro F1: {test_f1:.4f}")
    
    with open(os.path.join(ANALYSIS_DIR, "results.csv"), "w") as f:
        f.write("metric,value\n")
        f.write(f"best_val_macro_f1,{best_val_f1}\n")
        f.write(f"test_macro_f1,{test_f1}\n")
        
    return test_f1

def main():
    # A. No PRECEDES (Process only)
    f1_process = train_eval("process_only", ["INVOLVES", "SPAWNED"])
    
    # B. PRECEDES only
    f1_precedes = train_eval("precedes_only", ["PRECEDES"])
    
    # C. Process + PRECEDES
    f1_both = train_eval("process_and_precedes", ["INVOLVES", "SPAWNED", "PRECEDES"])
    
    # D. Full Graph
    f1_full = train_eval("full_graph", ["INVOLVES", "SPAWNED", "PRECEDES", "RUNS_ON", "EXECUTED_BY"])
    
    results = {
        "Process Only": f1_process,
        "PRECEDES Only": f1_precedes,
        "Process + PRECEDES": f1_both,
        "Full Graph": f1_full
    }
    
    print("\nFINAL GRAPH MODEL COMPARISON")
    for k, v in results.items():
        print(f"{k}: Test Macro-F1 = {v:.4f}")

if __name__ == "__main__":
    main()
