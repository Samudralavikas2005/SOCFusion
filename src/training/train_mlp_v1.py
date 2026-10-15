import os
import json
import pickle
import torch
import torch.optim as optim
import torch.nn.functional as F
import numpy as np
from sklearn.metrics import f1_score, accuracy_score, balanced_accuracy_score, precision_score, recall_score, confusion_matrix
import csv
import sys
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.mlp_v1 import SOCFusionMLP
from src.models.losses import FocalLoss

def load_event_data(filepath):
    print(f"Loading {filepath}...")
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
        
    nodes = data_dict['nodes']
    
    x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    
    return x, y

def main():
    OUTPUT_DIR = "data/processed/mlp_v1"
    ANALYSIS_DIR = "data/analysis/mlp_v1"
    os.makedirs(os.path.join(OUTPUT_DIR, "checkpoints"), exist_ok=True)
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
        "device": "cuda" if torch.cuda.is_available() else "cpu",
        "input_dim": 17,
        "hidden_dim": 64,
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
    
    x_train, y_train = load_event_data("data/processed/graphs_v2/train_data.pt")
    x_val, y_val = load_event_data("data/processed/graphs_v2/val_data.pt")
    x_test, y_test = load_event_data("data/processed/graphs_v2/test_data.pt")
    
    x_train, y_train = x_train.to(device), y_train.to(device)
    x_val, y_val = x_val.to(device), y_val.to(device)
    x_test, y_test = x_test.to(device), y_test.to(device)
    
    track_b_tensor = torch.tensor(CONFIG["track_b_classes"], device=device)
    
    # CLASS WEIGHTS
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
    alpha = alpha / alpha.sum() * num_present
    
    for b_idx in CONFIG["track_b_classes"]:
        alpha[b_idx] = 0.0
        
    with open(os.path.join(ANALYSIS_DIR, "class_weights.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "weight"])
        for i, a in enumerate(alpha):
            writer.writerow([i, float(a.item())])
            
    criterion = FocalLoss(alpha=alpha.cpu(), gamma=CONFIG["gamma"]).to(device)
    
    model = SOCFusionMLP(
        input_dim=CONFIG["input_dim"],
        hidden_dim=CONFIG["hidden_dim"], 
        num_classes=CONFIG["num_classes"]
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG["learning_rate"], weight_decay=CONFIG["weight_decay"])
    
    epochs = CONFIG["max_epochs"]
    patience = CONFIG["early_stopping_patience"]
    best_val_f1 = -1
    best_epoch = -1
    patience_counter = 0
    
    training_history = []
    
    print("Starting MLP V1 Training...")
    start_time = time.time()
    
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out = model(x_train)
        
        # Explicit mask for training loss
        loss = criterion(out[train_track_a_mask], y_train_a)
        
        if torch.isnan(loss) or torch.isinf(loss):
            print(f"Loss is NaN/Inf at epoch {epoch+1}")
            break
            
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            val_out = model(x_val)
            
            val_track_a_mask = ~torch.isin(y_val, track_b_tensor)
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
        test_out = model(x_test)
        
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

    print("Controlled MLP V1 Training Completed.")

if __name__ == "__main__":
    main()
