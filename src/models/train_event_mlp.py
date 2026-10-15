import os
import json
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import TensorDataset, DataLoader
from sklearn.metrics import f1_score, accuracy_score, balanced_accuracy_score
import time
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.losses import FocalLoss

class EventMLP(nn.Module):
    def __init__(self, input_dim, hidden_dim=128, num_classes=12, dropout=0.3):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, num_classes)
        )
        
    def forward(self, x):
        return self.net(x)

def main():
    FEAT_CSV = "data/processed/features_v3/features.csv"
    SCHEMA = "data/processed/features_v3/feature_schema.json"
    HOST_PART = "data/analysis/split_v2/host_partition.csv"
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    
    OUT_DIR = "data/processed/event_mlp"
    ANALYSIS_DIR = "data/analysis/event_mlp"
    os.makedirs(os.path.join(OUT_DIR, "checkpoints"), exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    print("Loading schema and mapping...")
    with open(SCHEMA, 'r') as f:
        schema = json.load(f)
    feature_cols = schema["feature_fields"] + schema["ohe_fields"]
    input_dim = len(feature_cols)
    
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    track_a_mapped.sort()
    a_to_idx = {orig: i for i, orig in enumerate(track_a_mapped)}
    
    print("Loading features...")
    df = pd.read_csv(FEAT_CSV, dtype={col: 'float32' for col in feature_cols}, low_memory=False)
    host_part = pd.read_csv(HOST_PART)
    df = df.merge(host_part, on="host", how="left")
    
    df = df[df["technique_id"].isin(TRACK_A_CLASSES)].copy()
    df['y'] = df['technique_id'].map(lambda x: a_to_idx[label_map[x]])
    
    train_df = df[df["partition"] == "train"]
    val_df = df[df["partition"] == "val"]
    test_df = df[df["partition"] == "test"]
    
    X_train = torch.tensor(train_df[feature_cols].values, dtype=torch.float32)
    y_train = torch.tensor(train_df['y'].values, dtype=torch.long)
    X_val = torch.tensor(val_df[feature_cols].values, dtype=torch.float32)
    y_val = torch.tensor(val_df['y'].values, dtype=torch.long)
    X_test = torch.tensor(test_df[feature_cols].values, dtype=torch.float32)
    y_test = torch.tensor(test_df['y'].values, dtype=torch.long)
    
    print(f"Train: {len(X_train)}, Val: {len(X_val)}, Test: {len(X_test)}")
    
    # Class weights for focal loss
    class_counts = torch.bincount(y_train, minlength=12).float()
    alpha = torch.zeros(12)
    present = class_counts > 0
    alpha[present] = 1.0 / class_counts[present]
    alpha = alpha / alpha.sum() * present.sum()
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = EventMLP(input_dim=input_dim, hidden_dim=128, num_classes=12, dropout=0.3).to(device)
    criterion = FocalLoss(alpha=alpha.to(device), gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=0.001, weight_decay=1e-4)
    
    train_loader = DataLoader(TensorDataset(X_train, y_train), batch_size=2048, shuffle=True)
    
    best_val_f1 = -1
    best_epoch = -1
    patience = 20
    patience_counter = 0
    
    print("Training MLP...")
    start_time = time.time()
    for epoch in range(150):
        model.train()
        total_loss = 0
        for bx, by in train_loader:
            bx, by = bx.to(device), by.to(device)
            optimizer.zero_grad()
            out = model(bx)
            loss = criterion(out, by)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        model.eval()
        with torch.no_grad():
            out_val = model(X_val.to(device))
            val_loss = criterion(out_val, y_val.to(device)).item()
            y_val_pred = out_val.argmax(dim=-1).cpu().numpy()
            
            val_f1 = f1_score(y_val.numpy(), y_val_pred, average='macro', zero_division=0)
            
        print(f"Epoch {epoch+1:03d} | Train Loss: {total_loss/len(train_loader):.4f} | Val Loss: {val_loss:.4f} | Val F1: {val_f1:.4f}")
        
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_epoch = epoch
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
        out_test = model(X_test.to(device))
        y_test_pred = out_test.argmax(dim=-1).cpu().numpy()
        test_f1 = f1_score(y_test.numpy(), y_test_pred, average='macro', zero_division=0)
        
    print(f"MLP Evaluation Complete. Test Macro F1: {test_f1:.4f}")
    
    with open(os.path.join(ANALYSIS_DIR, "mlp_results.csv"), "w") as f:
        f.write("metric,value\n")
        f.write(f"best_val_macro_f1,{best_val_f1}\n")
        f.write(f"test_macro_f1,{test_f1}\n")
        
    print("Done.")

if __name__ == "__main__":
    main()
