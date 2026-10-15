import os
import torch
import torch.nn.functional as F
import csv
import sys
import pickle
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T
import warnings
warnings.filterwarnings("ignore")

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.models.losses import FocalLoss
from src.models.gat import SOCFusionGAT
import json

OUT_DIR = "data/analysis/gat_v1_diagnostic"
os.makedirs(OUT_DIR, exist_ok=True)

print("Starting diagnostic tests...")

# ---------------------------------------------------------
# 1. Manual Loss Sanity Test
# ---------------------------------------------------------
print("Running Loss Sanity Test...")
# Load weights
weights = []
with open("data/analysis/gat_v1/class_weights.csv", "r") as f:
    reader = csv.reader(f)
    next(reader)
    for row in reader:
        weights.append(float(row[1]))
alpha = torch.tensor(weights, dtype=torch.float32)

# Synthetic data
logits = torch.zeros(3, 15)
logits[0, 7] = 10.0 
logits[1, 1] = 10.0
targets = torch.tensor([7, 7, 7], dtype=torch.long)

focal_loss_fn = FocalLoss(alpha=alpha, gamma=2.0, reduction='none')
focal_losses = focal_loss_fn(logits, targets)

ce_loss_fn = torch.nn.CrossEntropyLoss(reduction='none')
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
    
with open(os.path.join(OUT_DIR, "focal_loss_sanity.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["scenario", "target", "cross_entropy", "focal_loss"])
    writer.writeheader()
    writer.writerows(results_loss)

# ---------------------------------------------------------
# 2. Graph/Feature Audit
# ---------------------------------------------------------
print("Running Feature & Graph Audit...")
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
            
    data = T.ToUndirected()(data)
    return data

train_data = load_graph("data/processed/graphs_v1/train_data.pt")
val_data = load_graph("data/processed/graphs_v1/val_data.pt")
test_data = load_graph("data/processed/graphs_v1/test_data.pt")

x = train_data['Event'].x
feat_stats = {
    "tensor_shape": str(list(x.shape)),
    "dtype": str(x.dtype),
    "min": x.min().item(),
    "max": x.max().item(),
    "mean": x.mean().item(),
    "std": x.std().item(),
    "nan_count": torch.isnan(x).sum().item(),
    "inf_count": torch.isinf(x).sum().item()
}
with open(os.path.join(OUT_DIR, "feature_statistics.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=feat_stats.keys())
    writer.writeheader()
    writer.writerow(feat_stats)

# ---------------------------------------------------------
# 3. Model Output & Gradient Audit
# ---------------------------------------------------------
print("Running Model Output and Gradient Audit...")
device = torch.device('cpu')
model = SOCFusionGAT(
    hidden_dim=64, 
    num_heads=4, 
    num_classes=15, 
    edge_types=train_data.edge_types,
    num_hosts=train_data['Host'].num_nodes,
    num_users=train_data['User'].num_nodes,
    num_processes=train_data['Process'].num_nodes
).to(device)

model.load_state_dict(torch.load("data/processed/gat_v1/checkpoints/best_model.pth", map_location=device))

# Output Audit
model.eval()
output_stats = []
pred_dist = []
splits = [("train", train_data), ("val", val_data), ("test", test_data)]

with torch.no_grad():
    for name, data in splits:
        out, _ = model(data.x_dict, data.edge_index_dict)
        probs = F.softmax(out, dim=-1)
        preds = out.argmax(dim=-1)
        
        output_stats.append({
            "split": name,
            "logits_min": out.min().item(),
            "logits_max": out.max().item(),
            "logits_mean": out.mean().item(),
            "probs_min": probs.min().item(),
            "probs_max": probs.max().item(),
            "probs_mean": probs.mean().item()
        })
        
        # Predicted vs Target Distribution
        y_true = data['Event'].y
        for c in range(15):
            pred_count = (preds == c).sum().item()
            true_count = (y_true == c).sum().item()
            if pred_count > 0 or true_count > 0:
                pred_dist.append({
                    "split": name,
                    "class_idx": c,
                    "predicted_count": pred_count,
                    "target_count": true_count
                })

with open(os.path.join(OUT_DIR, "model_output_statistics.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["split", "logits_min", "logits_max", "logits_mean", "probs_min", "probs_max", "probs_mean"])
    writer.writeheader()
    writer.writerows(output_stats)
    
with open(os.path.join(OUT_DIR, "prediction_distribution.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["split", "class_idx", "predicted_count", "target_count"])
    writer.writeheader()
    writer.writerows(pred_dist)

# Gradient Audit
model.train()
model.zero_grad()
out, _ = model(train_data.x_dict, train_data.edge_index_dict)
loss = focal_loss_fn(out, train_data['Event'].y).mean()
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
with open(os.path.join(OUT_DIR, "gradient_audit.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["loss", "total_gradient_norm", "min_gradient_magnitude", "max_gradient_magnitude", "has_nan_inf"])
    writer.writeheader()
    writer.writerow(grad_stats)

print("Diagnostic tests complete.")
