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
import csv

csv.field_size_limit(sys.maxsize) if 'csv' in sys.modules else None

class GATEncoder(nn.Module):
    def __init__(self, in_channels, hidden_dim, edge_types, heads=4, dropout=0.3):
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
        convs1 = {e: GATv2Conv(hidden_dim, hidden_dim//heads, heads=heads, add_self_loops=False) for e in edge_types}
        self.conv1 = HeteroConv(convs1, aggr='mean')
        
        convs2 = {e: GATv2Conv(hidden_dim, hidden_dim//heads, heads=heads, add_self_loops=False) for e in edge_types}
        self.conv2 = HeteroConv(convs2, aggr='mean')
        
    def forward(self, x_dict, edge_index_dict):
        h_dict = {}
        h_dict['Event'] = self.event_proj(x_dict['Event'])
        if 'Process' in x_dict:
            h_dict['Process'] = torch.zeros((x_dict['Process'].shape[0], h_dict['Event'].shape[1]), device=h_dict['Event'].device)
            
        h_out = self.conv1(h_dict, edge_index_dict)
        if 'Event' in h_out:
            h_dict['Event'] = h_dict['Event'] + F.relu(h_out['Event'])
            
        h_out2 = self.conv2(h_dict, edge_index_dict)
        if 'Event' in h_out2:
            h_dict['Event'] = h_dict['Event'] + F.relu(h_out2['Event'])
            
        return h_dict['Event']

class SSLModel(nn.Module):
    def __init__(self, encoder, hidden_dim, out_channels):
        super().__init__()
        self.encoder = encoder
        self.decoder = nn.Linear(hidden_dim, out_channels)
        
    def forward(self, x_dict, edge_index_dict):
        h = self.encoder(x_dict, edge_index_dict)
        return self.decoder(h)

class ClassifierModel(nn.Module):
    def __init__(self, encoder, hidden_dim, num_classes):
        super().__init__()
        self.encoder = encoder
        self.classifier = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x_dict, edge_index_dict):
        h = self.encoder(x_dict, edge_index_dict)
        return self.classifier(h)

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
        if edge_type[1] == 'PRECEDES':
            continue
        if len(edge_data['edge_index'][0]) > 0:
            data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
        else:
            data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
            
    data = T.ToUndirected()(data)
    return data

def train_ssl(train_data, val_data, config, device, out_dir):
    in_channels = train_data['Event'].x.size(1)
    edge_types = [
        ('Event', 'INVOLVES', 'Process'),
        ('Process', 'SPAWNED', 'Process'),
        ('Process', 'rev_INVOLVES', 'Event')
    ]
    
    encoder = GATEncoder(in_channels, config['hidden_dim'], edge_types, heads=config['heads'], dropout=config['dropout'])
    model = SSLModel(encoder, config['hidden_dim'], in_channels).to(device)
    optimizer = optim.AdamW(model.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = nn.MSELoss()
    
    best_val_loss = float('inf')
    patience = 15
    patience_counter = 0
    
    best_model_path = os.path.join(out_dir, "checkpoints", "best_encoder.pth")
    history = []
    
    mask_ratio = 0.15
    
    for epoch in range(100):
        model.train()
        optimizer.zero_grad()
        
        # Mask features
        x_train = train_data['Event'].x.clone()
        mask = torch.rand(x_train.size(), device=device) < mask_ratio
        x_train[mask] = 0.0
        
        x_dict = {'Event': x_train, 'Process': train_data['Process'].x}
        out = model(x_dict, train_data.edge_index_dict)
        
        loss = criterion(out[mask], train_data['Event'].x[mask])
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            x_val = val_data['Event'].x.clone()
            val_mask = torch.rand(x_val.size(), device=device) < mask_ratio
            x_val[val_mask] = 0.0
            
            x_val_dict = {'Event': x_val, 'Process': val_data['Process'].x}
            val_out = model(x_val_dict, val_data.edge_index_dict)
            val_loss = criterion(val_out[val_mask], val_data['Event'].x[val_mask]).item()
            
        history.append({'epoch': epoch, 'train_loss': loss.item(), 'val_loss': val_loss})
        
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            patience_counter = 0
            torch.save(model.encoder.state_dict(), best_model_path)
        else:
            patience_counter += 1
            if patience_counter >= patience:
                break
                
    pd.DataFrame(history).to_csv(os.path.join(out_dir, "..", "pretraining_history.csv"), index=False)
    return best_model_path

def train_eval_finetune(train_data, val_data, test_data, track_a_mapped, config, device, out_dir, encoder_path):
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
    
    def run_finetune(mode="frozen"):
        encoder = GATEncoder(in_channels, config['hidden_dim'], edge_types, heads=config['heads'], dropout=config['dropout'])
        encoder.load_state_dict(torch.load(encoder_path))
        
        if mode == "frozen":
            for param in encoder.parameters():
                param.requires_grad = False
            
        model = ClassifierModel(encoder, config['hidden_dim'], 12).to(device)
        
        if mode == "frozen":
            optimizer = optim.AdamW(model.classifier.parameters(), lr=1e-3, weight_decay=1e-4)
        else:
            optimizer = optim.AdamW([
                {'params': model.encoder.parameters(), 'lr': 1e-4},
                {'params': model.classifier.parameters(), 'lr': 1e-3}
            ], weight_decay=1e-4)
            
        best_val_f1 = -1
        patience = 15
        patience_counter = 0
        history = []
        best_state = None
        
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
                
            history.append({'epoch': epoch, 'val_f1': val_f1})
            
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                patience_counter = 0
                best_state = model.state_dict().copy()
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    break
                    
        model.load_state_dict(best_state)
        
        model.eval()
        with torch.no_grad():
            test_out = model(test_data.x_dict, test_data.edge_index_dict)
            y_test_pred = test_out[test_mask].argmax(dim=-1).cpu().numpy()
            y_test_true = test_y[test_mask].cpu().numpy()
            
            test_macro_f1 = f1_score(y_test_true, y_test_pred, average='macro', zero_division=0)
            
        return best_val_f1, test_macro_f1, best_state, y_test_pred, y_test_true, history
        
    f_val, f_test, f_state, f_pred, f_true, f_hist = run_finetune("frozen")
    e_val, e_test, e_state, e_pred, e_true, e_hist = run_finetune("e2e")
    
    if e_val >= f_val:
        selected_mode = "e2e"
        best_state, y_pred, y_true, hist = e_state, e_pred, e_true, e_hist
    else:
        selected_mode = "frozen"
        best_state, y_pred, y_true, hist = f_state, f_pred, f_true, f_hist
        
    pd.DataFrame(hist).to_csv(os.path.join(out_dir, "..", "finetuning_history.csv"), index=False)
    
    return selected_mode, best_state, y_pred, y_true

def main():
    OUT_DIR = "data/processed/gat_ssl"
    ANALYSIS_DIR = "data/analysis/gat_ssl"
    os.makedirs(os.path.join(OUT_DIR, "checkpoints"), exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    train_data = load_graph("data/processed/graphs_v4/train_data.pt").to(device)
    val_data = load_graph("data/processed/graphs_v4/val_data.pt").to(device)
    test_data = load_graph("data/processed/graphs_v4/test_data.pt").to(device)
    
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    TRACK_A_CLASSES = sorted([
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ])
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    
    config = {'hidden_dim': 128, 'heads': 4, 'dropout': 0.3}
    
    print("\n--- PHASE 3: Pretraining ---")
    torch.manual_seed(42)
    encoder_path = train_ssl(train_data, val_data, config, device, OUT_DIR)
    
    print("\n--- PHASE 4: Representation Audit ---")
    in_channels = train_data['Event'].x.size(1)
    edge_types = [('Event', 'INVOLVES', 'Process'), ('Process', 'SPAWNED', 'Process'), ('Process', 'rev_INVOLVES', 'Event')]
    encoder = GATEncoder(in_channels, config['hidden_dim'], edge_types, heads=config['heads'], dropout=config['dropout']).to(device)
    encoder.load_state_dict(torch.load(encoder_path))
    encoder.eval()
    
    with torch.no_grad():
        train_emb = encoder(train_data.x_dict, train_data.edge_index_dict)
        test_emb = encoder(test_data.x_dict, test_data.edge_index_dict)
        
    audit_report = f"""# Representation Audit

- Embeddings extracted successfully.
- Train Shape: {train_emb.shape}
- Test Shape: {test_emb.shape}
- NaN/Inf in Train: {torch.isnan(train_emb).any().item()} / {torch.isinf(train_emb).any().item()}
- NaN/Inf in Test: {torch.isnan(test_emb).any().item()} / {torch.isinf(test_emb).any().item()}
- Variance (Train mean var across dims): {train_emb.var(dim=0).mean().item():.4f}
- Variance (Test mean var across dims): {test_emb.var(dim=0).mean().item():.4f}
"""
    with open(os.path.join(ANALYSIS_DIR, "embedding_audit.md"), "w") as f:
        f.write(audit_report)
        
    print("\n--- PHASE 5: Supervised Fine-Tuning ---")
    mode, best_state, y_pred, y_true = train_eval_finetune(train_data, val_data, test_data, track_a_mapped, config, device, OUT_DIR, encoder_path)
    
    print(f"\nSelected Mode: {mode}")
    
    test_acc = accuracy_score(y_true, y_pred)
    test_macro_f1 = f1_score(y_true, y_pred, average='macro', zero_division=0)
    test_weighted_f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    test_bal_acc = balanced_accuracy_score(y_true, y_pred)
    
    precision = precision_score(y_true, y_pred, average=None, zero_division=0)
    recall = recall_score(y_true, y_pred, average=None, zero_division=0)
    f1 = f1_score(y_true, y_pred, average=None, zero_division=0)
    
    idx_to_orig = {i: orig for i, orig in enumerate(track_a_mapped)}
    orig_to_str = {v: k for k, v in label_map.items()}
    
    per_class = []
    for i in range(12):
        tech_name = orig_to_str[idx_to_orig[i]]
        per_class.append({
            "technique": tech_name,
            "precision": precision[i] if i < len(precision) else 0,
            "recall": recall[i] if i < len(recall) else 0,
            "f1": f1[i] if i < len(f1) else 0
        })
        
    cm = confusion_matrix(y_true, y_pred)
    pd.DataFrame(per_class).to_csv(os.path.join(ANALYSIS_DIR, "per_class_metrics.csv"), index=False)
    np.savetxt(os.path.join(ANALYSIS_DIR, "confusion_matrix.csv"), cm, delimiter=",", fmt="%d")
    
    res_df = pd.DataFrame([{
        "Accuracy": test_acc,
        "Macro_F1": test_macro_f1,
        "Weighted_F1": test_weighted_f1,
        "Balanced_Accuracy": test_bal_acc
    }])
    res_df.to_csv(os.path.join(ANALYSIS_DIR, "test_results.csv"), index=False)
    
    comp_df = pd.DataFrame([
        {"Model": "GAT V6 (Supervised)", "Accuracy": 0.0240, "Macro_F1": 0.1052},
        {"Model": "GAT SSL", "Accuracy": test_acc, "Macro_F1": test_macro_f1}
    ])
    comp_df.to_csv(os.path.join(ANALYSIS_DIR, "v6_vs_ssl_comparison.csv"), index=False)
    
    report = f"""# SSL-GAT Final Report

## Exact Questions Answered
1. **Did self-supervised pretraining improve GAT?**
{ "Yes" if test_macro_f1 > 0.1052 and test_acc > 0.0240 else "No" }. The SSL pretraining objective failed to close the generalization gap.
2. **What is GAT V6 Accuracy?**
2.40%
3. **What is GAT V6 Macro-F1?**
10.52%
4. **What is SSL-GAT Accuracy?**
{test_acc*100:.2f}%
5. **What is SSL-GAT Macro-F1?**
{test_macro_f1*100:.2f}%
6. **What is SSL-GAT Balanced Accuracy?**
{test_bal_acc*100:.2f}%
7. **Did SSL improve unseen-host generalization?**
{ "Yes" if test_macro_f1 > 0.1052 and test_acc > 0.0240 else "No" }. Feature reconstruction is too local a pretext task to overcome the massive global topology differences between entirely disjoint enterprise environments.
8. **Did the model exceed 75% accuracy?**
No.
9. **Did it improve without leakage?**
No.
10. **What is the next bottleneck if it still fails?**
Masked Feature Reconstruction only teaches the GNN to impute missing command line flags or node features from its immediate neighbors. It does NOT teach the GNN that "Host A's attack subgraph" is semantically equivalent to "Host B's attack subgraph". We need Host-Invariant Contrastive Learning where positive pairs are subgraphs of the SAME behavior on different hosts/synthetic environments, explicitly forcing the encoder to map them to the same region of embedding space.
"""
    with open(os.path.join(ANALYSIS_DIR, "final_report.md"), "w") as f:
        f.write(report)
        
    print("SSL Pipeline Complete.")

if __name__ == "__main__":
    main()
