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

from src.models.gat import SOCFusionGAT
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
    OUTPUT_DIR = "data/processed/gat_v1_corrected"
    ANALYSIS_DIR = "data/analysis/gat_v1_corrected"
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
        "gamma": 2.0
    }
    
    with open(os.path.join(ANALYSIS_DIR, "training_config.json"), "w") as f:
        json.dump(CONFIG, f, indent=4)
        
    torch.manual_seed(CONFIG["random_seed"])
    np.random.seed(CONFIG["random_seed"])
    
    device = torch.device(CONFIG["device"])
    print(f"Using device: {device}")
    
    train_data = load_graph("data/processed/graphs_v1/train_data.pt")
    val_data = load_graph("data/processed/graphs_v1/val_data.pt")
    test_data = load_graph("data/processed/graphs_v1/test_data.pt")
    
    edge_types = train_data.edge_types
    print("Edge types found:", edge_types)
    
    # 2. CORRECT CLASS WEIGHTING
    y_train = train_data['Event'].y
    class_counts = torch.bincount(y_train, minlength=CONFIG["num_classes"]).float()
    
    with open(os.path.join(ANALYSIS_DIR, "class_distribution.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "count"])
        for i, c in enumerate(class_counts):
            writer.writerow([i, int(c.item())])
            
    # New weighting logic
    alpha = torch.zeros(CONFIG["num_classes"])
    present_classes = (class_counts > 0)
    alpha[present_classes] = 1.0 / class_counts[present_classes]
    
    num_present = present_classes.sum().item()
    alpha = alpha / alpha.sum() * num_present
    
    with open(os.path.join(ANALYSIS_DIR, "class_weights.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "weight"])
        for i, a in enumerate(alpha):
            writer.writerow([i, float(a.item())])
            
    alpha = alpha.to(device)
    
    # LOSS SANITY CHECK
    print("Running Loss Sanity Check with corrected weights...")
    logits = torch.zeros(3, 15)
    logits[0, 7] = 10.0 
    logits[1, 1] = 10.0
    targets = torch.tensor([7, 7, 7], dtype=torch.long)
    focal_loss_fn = FocalLoss(alpha=alpha.cpu(), gamma=CONFIG["gamma"], reduction='none')
    ce_loss_fn = torch.nn.CrossEntropyLoss(reduction='none')
    focal_losses = focal_loss_fn(logits, targets)
    ce_losses = ce_loss_fn(logits, targets)
    
    results_loss = []
    scenarios = ["correct_high_conf", "incorrect_high_conf", "uniform"]
    for i in range(3):
        results_loss.append({
            "scenario": scenarios[i],
            "target": targets[i].item(),
            "cross_entropy": ce_losses[i].item(),
            "focal_loss": focal_losses[i].item()
        })
        
    with open(os.path.join(ANALYSIS_DIR, "focal_loss_sanity.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["scenario", "target", "cross_entropy", "focal_loss"])
        writer.writeheader()
        writer.writerows(results_loss)
        
    # GRADIENT AUDIT
    print("Running Gradient Audit...")
    model = SOCFusionGAT(
        hidden_dim=CONFIG["hidden_dim"], 
        num_heads=CONFIG["num_heads"], 
        num_classes=CONFIG["num_classes"], 
        edge_types=edge_types,
        num_hosts=train_data['Host'].num_nodes,
        num_users=train_data['User'].num_nodes,
        num_processes=train_data['Process'].num_nodes
    ).to(device)
    
    criterion = FocalLoss(alpha=alpha, gamma=CONFIG["gamma"])
    train_data = train_data.to(device)
    
    model.train()
    model.zero_grad()
    out, _ = model(train_data.x_dict, train_data.edge_index_dict)
    loss = criterion(out, train_data['Event'].y)
    loss.backward()

    total_norm = 0.0
    min_grad = float('inf')
    max_grad = float('-inf')
    has_nan_inf = False

    for p in model.parameters():
        if p.grad is not None:
            param_norm = p.grad.data.norm(2).item()
            total_norm += param_norm ** 2
            min_grad = min(min_grad, p.grad.min().item())
            max_grad = max(max_grad, p.grad.max().item())
            if torch.isnan(p.grad).any() or torch.isinf(p.grad).any():
                has_nan_inf = True
    total_norm = total_norm ** 0.5

    grad_stats = {
        "loss": loss.item(),
        "total_gradient_norm": total_norm,
        "min_gradient_magnitude": min_grad,
        "max_gradient_magnitude": max_grad,
        "has_nan_inf": has_nan_inf
    }
    with open(os.path.join(ANALYSIS_DIR, "gradient_audit.csv"), "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["loss", "total_gradient_norm", "min_gradient_magnitude", "max_gradient_magnitude", "has_nan_inf"])
        writer.writeheader()
        writer.writerow(grad_stats)
        
    print(f"Gradient Audit -> Loss: {loss.item():.4f}, Norm: {total_norm:.4f}")
    
    # RE-INITIALIZE FOR TRAINING
    model = SOCFusionGAT(
        hidden_dim=CONFIG["hidden_dim"], 
        num_heads=CONFIG["num_heads"], 
        num_classes=CONFIG["num_classes"], 
        edge_types=edge_types,
        num_hosts=train_data['Host'].num_nodes,
        num_users=train_data['User'].num_nodes,
        num_processes=train_data['Process'].num_nodes
    ).to(device)
    
    optimizer = optim.AdamW(model.parameters(), lr=CONFIG["learning_rate"], weight_decay=CONFIG["weight_decay"])
    
    val_data = val_data.to(device)
    test_data = test_data.to(device)
    
    epochs = CONFIG["max_epochs"]
    patience = CONFIG["early_stopping_patience"]
    best_val_f1 = -1
    best_epoch = -1
    patience_counter = 0
    
    training_history = []
    
    print("Starting Corrected Baseline Training...")
    start_time = time.time()
    
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        out, _ = model(train_data.x_dict, train_data.edge_index_dict)
        loss = criterion(out, train_data['Event'].y)
        loss.backward()
        optimizer.step()
        
        model.eval()
        with torch.no_grad():
            val_out, _ = model(val_data.x_dict, val_data.edge_index_dict)
            val_loss = criterion(val_out, val_data['Event'].y)
            
            val_pred = val_out.argmax(dim=-1).cpu().numpy()
            y_val_true = val_data['Event'].y.cpu().numpy()
            
            val_macro_f1 = f1_score(y_val_true, val_pred, average='macro', zero_division=0)
            val_weighted_f1 = f1_score(y_val_true, val_pred, average='weighted', zero_division=0)
            val_acc = accuracy_score(y_val_true, val_pred)
            val_bal_acc = balanced_accuracy_score(y_val_true, val_pred)
            
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
        
    print("Loading best model for test evaluation...")
    model.load_state_dict(torch.load(os.path.join(OUTPUT_DIR, "checkpoints", "best_model.pth")))
    model.eval()
    
    with torch.no_grad():
        train_out, train_emb = model(train_data.x_dict, train_data.edge_index_dict)
        torch.save(train_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "train_embeddings.pt"))
        
        val_out, val_emb = model(val_data.x_dict, val_data.edge_index_dict)
        torch.save(val_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "val_embeddings.pt"))
        
        test_out, test_emb = model(test_data.x_dict, test_data.edge_index_dict)
        torch.save(test_emb.cpu(), os.path.join(OUTPUT_DIR, "embeddings", "test_embeddings.pt"))
        
        test_pred = test_out.argmax(dim=-1).cpu().numpy()
        y_test_true = test_data['Event'].y.cpu().numpy()
        
        labels_list = list(range(CONFIG["num_classes"]))
        test_macro_f1 = f1_score(y_test_true, test_pred, average='macro', zero_division=0)
        test_weighted_f1 = f1_score(y_test_true, test_pred, average='weighted', zero_division=0)
        test_acc = accuracy_score(y_test_true, test_pred)
        test_bal_acc = balanced_accuracy_score(y_test_true, test_pred)
        
        precision = precision_score(y_test_true, test_pred, labels=labels_list, average=None, zero_division=0)
        recall = recall_score(y_test_true, test_pred, labels=labels_list, average=None, zero_division=0)
        f1 = f1_score(y_test_true, test_pred, labels=labels_list, average=None, zero_division=0)
        
    final_test_metrics = {
        "Accuracy": test_acc,
        "Macro-F1": test_macro_f1,
        "Weighted-F1": test_weighted_f1,
        "Balanced Accuracy": test_bal_acc
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
        for i in range(CONFIG["num_classes"]):
            writer.writerow([i, precision[i], recall[i], f1[i]])
            
    with open(os.path.join(ANALYSIS_DIR, "per_class_metrics.csv"), "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["class_idx", "precision", "recall", "f1"])
        for i in range(CONFIG["num_classes"]):
            writer.writerow([i, precision[i], recall[i], f1[i]])
            
    cm = confusion_matrix(y_test_true, test_pred, labels=labels_list)
    np.savetxt(os.path.join(OUTPUT_DIR, "metrics", "confusion_matrix.csv"), cm, delimiter=",", fmt='%d')
    np.savetxt(os.path.join(ANALYSIS_DIR, "confusion_matrix.csv"), cm, delimiter=",", fmt='%d')

    print("Corrected Baseline Training Completed. Generate report next.")

if __name__ == "__main__":
    main()
