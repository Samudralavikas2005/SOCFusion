import os
import json
import pickle
import torch
import torch.optim as optim
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import f1_score, accuracy_score, balanced_accuracy_score, precision_score, recall_score, confusion_matrix
import csv
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.gat_v4 import SOCFusionGATv4
from src.models.losses import FocalLoss

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

def main():
    OUTPUT_DIR = "data/processed/gat_v4"
    ANALYSIS_DIR = "data/analysis/gat_v4"
    os.makedirs(os.path.join(OUTPUT_DIR, "checkpoints"), exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "embeddings"), exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "metrics"), exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    CONFIG = {
        "learning_rate": 0.005,
        "optimizer": "AdamW",
        "weight_decay": 1e-4,
        "dropout": 0.3,
        "max_epochs": 150,
        "early_stopping_patience": 20,
        "random_seed": 42,
        "batch_strategy": "full-graph",
        "device": "cuda" if torch.cuda.is_available() else "cpu",
        "hidden_dim": 64,
        "num_heads": 4,
        "num_classes": 15,
        "gamma": 2.0,
        "track_a_classes": [0, 1, 2, 4, 5, 6, 7, 10, 11, 12, 13, 14],
        "track_b_classes": [3, 8, 9]
    }
    
    with open(os.path.join(ANALYSIS_DIR, "training_config.json"), "w") as f:
        json.dump(CONFIG, f, indent=4)
        
    torch.manual_seed(CONFIG["random_seed"])
    np.random.seed(CONFIG["random_seed"])
    
    device = torch.device(CONFIG["device"])
    print(f"Using device: {device}")
    
    train_data = load_graph("data/processed/graphs_v2/train_data.pt").to(device)
    val_data = load_graph("data/processed/graphs_v2/val_data.pt").to(device)
    test_data = load_graph("data/processed/graphs_v2/test_data.pt").to(device)
    
    edge_types = train_data.edge_types
    print("Edge types found:", edge_types)
    
    track_b_tensor = torch.tensor(CONFIG["track_b_classes"], device=device)
    
    # 1. CLASS WEIGHTS
    y_train = train_data['Event'].y
    train_track_a_mask = ~torch.isin(y_train, track_b_tensor)
    y_train_a = y_train[train_track_a_mask]
    
    print(f"Total training events: {y_train.size(0)}")
    print(f"Track A training events: {y_train_a.size(0)}")
    print(f"Track B training events excluded: {y_train.size(0) - y_train_a.size(0)}")
    
    class_counts = torch.bincount(y_train_a, minlength=CONFIG["num_classes"]).float()
    
    with open(os.path.join(ANALYSIS_DIR, "class_distribution.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "count"])
        for i, c in enumerate(class_counts):
            writer.writerow([i, int(c.item())])
            
    alpha = torch.zeros(CONFIG["num_classes"], device=device)
    present_classes = (class_counts > 0)
    alpha[present_classes] = 1.0 / class_counts[present_classes]
    
    # Normalize alpha ONLY over the 12 Track A classes
    num_present = present_classes.sum().item()
    if num_present != 12:
        print(f"WARNING: Expected 12 Track A classes, found {num_present}")
    
    alpha = alpha / alpha.sum() * num_present
    
    # Force track B weights to 0 just in case
    for b_idx in CONFIG["track_b_classes"]:
        alpha[b_idx] = 0.0
        
    with open(os.path.join(ANALYSIS_DIR, "class_weights.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "weight"])
        for i, a in enumerate(alpha):
            writer.writerow([i, float(a.item())])
            
    criterion = FocalLoss(alpha=alpha.cpu(), gamma=CONFIG["gamma"]).to(device)
    
    model = SOCFusionGATv4(
        hidden_dim=CONFIG["hidden_dim"], 
        num_heads=CONFIG["num_heads"], 
        num_classes=CONFIG["num_classes"], 
        edge_types=edge_types
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG["learning_rate"], weight_decay=CONFIG["weight_decay"])
    
    epochs = CONFIG["max_epochs"]
    patience = CONFIG["early_stopping_patience"]
    best_val_f1 = -1
    best_epoch = -1
    patience_counter = 0
    
    training_history = []
    
    print("Starting Controlled Experiment GAT V4 Training...")
    start_time = time.time()
    
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out, _ = model(train_data.x_dict, train_data.edge_index_dict)
        
        # Explicit mask for training loss
        loss = criterion(out[train_track_a_mask], y_train_a)
        
        if torch.isnan(loss) or torch.isinf(loss):
            print(f"Loss is NaN/Inf at epoch {epoch+1}")
            break
            
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            val_out, _ = model(val_data.x_dict, val_data.edge_index_dict)
            
            y_val = val_data['Event'].y
            val_track_a_mask = ~torch.isin(y_val, track_b_tensor)
            
            # Explicit mask for validation loss
            val_loss = criterion(val_out[val_track_a_mask], y_val[val_track_a_mask])
            
            val_pred = val_out.argmax(dim=-1).cpu().numpy()
            y_val_true = y_val.cpu().numpy()
            val_track_a_mask_np = val_track_a_mask.cpu().numpy()
            
            val_pred_a = val_pred[val_track_a_mask_np]
            y_val_true_a = y_val_true[val_track_a_mask_np]
            
            # Metrics on Track A ONLY
            val_macro_f1 = f1_score(y_val_true_a, val_pred_a, labels=CONFIG["track_a_classes"], average='macro', zero_division=0)
            val_weighted_f1 = f1_score(y_val_true_a, val_pred_a, labels=CONFIG["track_a_classes"], average='weighted', zero_division=0)
            val_acc = accuracy_score(y_val_true_a, val_pred_a)
            val_bal_acc = balanced_accuracy_score(y_val_true_a, val_pred_a)
            
            training_history.append({
                'epoch': epoch,
                'train_loss': loss.item(),
                'val_loss': val_loss.item(),
                'val_accuracy': val_acc,
                'val_macro_f1': val_macro_f1,
                'val_weighted_f1': val_weighted_f1,
                'val_balanced_acc': val_bal_acc
            })
            
            print(f"Epoch {epoch+1:03d} | Train Loss: {loss.item():.4f} | Val Loss: {val_loss.item():.4f} | Val Macro F1: {val_macro_f1:.4f}")
            
            if val_macro_f1 > best_val_f1:
                best_val_f1 = val_macro_f1
                best_epoch = epoch
                patience_counter = 0
                torch.save(model.state_dict(), os.path.join(OUTPUT_DIR, "checkpoints", "best_model.pth"))
            else:
                patience_counter += 1
                
        if patience_counter >= patience:
            print(f"Early stopping triggered at epoch {epoch+1}")
            break
            
    training_time = time.time() - start_time
    
    with open(os.path.join(ANALYSIS_DIR, "training_history.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=['epoch', 'train_loss', 'val_loss', 'val_accuracy', 'val_macro_f1', 'val_weighted_f1', 'val_balanced_acc'])
        writer.writeheader()
        writer.writerows(training_history)
        
    with open(os.path.join(ANALYSIS_DIR, "validation_results.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["best_epoch", best_epoch])
        writer.writerow(["best_val_macro_f1", best_val_f1])
        writer.writerow(["epochs_completed", epoch + 1])
        writer.writerow(["training_time_seconds", training_time])
        
    print("Loading best model for test evaluation...")
    model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "checkpoints", "best_model.pth")))
    model.eval()
    
    with torch.no_grad():
        # Saving embeddings
        train_out, train_emb = model(train_data.x_dict, train_data.edge_index_dict)
        torch.save(train_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "train_embeddings.pt"))
        
        val_out, val_emb = model(val_data.x_dict, val_data.edge_index_dict)
        torch.save(val_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "val_embeddings.pt"))
        
        test_out, test_emb = model(test_data.x_dict, test_data.edge_index_dict)
        torch.save(test_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "test_embeddings.pt"))
        
        # Test evaluation
        y_test = test_data['Event'].y
        test_track_a_mask = ~torch.isin(y_test, track_b_tensor)
        
        test_pred = test_out.argmax(dim=-1).cpu().numpy()
        y_test_true = y_test.cpu().numpy()
        
        test_track_a_mask_np = test_track_a_mask.cpu().numpy()
        test_pred_a = test_pred[test_track_a_mask_np]
        y_test_true_a = y_test_true[test_track_a_mask_np]
        
        test_b_count = (~test_track_a_mask_np).sum()
        print(f"Track B events excluded from test metrics: {test_b_count}")
        
        labels_list = CONFIG["track_a_classes"]
        test_macro_f1 = f1_score(y_test_true_a, test_pred_a, labels=labels_list, average='macro', zero_division=0)
        test_weighted_f1 = f1_score(y_test_true_a, test_pred_a, labels=labels_list, average='weighted', zero_division=0)
        test_acc = accuracy_score(y_test_true_a, test_pred_a)
        test_bal_acc = balanced_accuracy_score(y_test_true_a, test_pred_a)
        
        precision = precision_score(y_test_true_a, test_pred_a, labels=labels_list, average=None, zero_division=0)
        recall = recall_score(y_test_true_a, test_pred_a, labels=labels_list, average=None, zero_division=0)
        f1 = f1_score(y_test_true_a, test_pred_a, labels=labels_list, average=None, zero_division=0)
        
    final_test_metrics = {
        "Accuracy": test_acc,
        "Macro-F1": test_macro_f1,
        "Weighted-F1": test_weighted_f1,
        "Balanced Accuracy": test_bal_acc,
        "Excluded_Track_B_Events": int(test_b_count)
    }
    
    with open(os.path.join(OUTPUT_DIR, "metrics", "final_test_metrics.json"), "w") as f:
        json.dump(final_test_metrics, f, indent=4)
        
    with open(os.path.join(ANALYSIS_DIR, "test_results.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        for k, v in final_test_metrics.items():
            writer.writerow([k, v])
            
    with open(os.path.join(OUTPUT_DIR, "metrics", "per_class_metrics.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "precision", "recall", "f1"])
        for i, cls_idx in enumerate(labels_list):
            writer.writerow([cls_idx, precision[i], recall[i], f1[i]])
            
    with open(os.path.join(ANALYSIS_DIR, "per_class_metrics.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "precision", "recall", "f1"])
        for i, cls_idx in enumerate(labels_list):
            writer.writerow([cls_idx, precision[i], recall[i], f1[i]])
            
    cm = confusion_matrix(y_test_true_a, test_pred_a, labels=labels_list)
    np.savetxt(os.path.join(OUTPUT_DIR, "metrics", "confusion_matrix.csv"), cm, delimiter=",", fmt='%d')
    np.savetxt(os.path.join(ANALYSIS_DIR, "confusion_matrix.csv"), cm, delimiter=",", fmt='%d')

    print("Controlled GAT V4 Training Completed.")

if __name__ == "__main__":
    main()
