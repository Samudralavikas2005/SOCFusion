import pickle
import torch
import torch.nn.functional as F
from src.models.gat import SOCFusionGAT
from src.models.losses import FocalLoss
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T


def load_graph(filepath):
    with open(filepath, "rb") as f:
        data_dict = pickle.load(f)

    data = HeteroData()
    nodes = data_dict["nodes"]

    data["Event"].x = torch.tensor(
        nodes["Event"]["x"], dtype=torch.float32
    )
    data["Event"].y = torch.tensor(
        nodes["Event"]["y"], dtype=torch.long
    )
    data["Event"].num_nodes = nodes["Event"]["num_nodes"]

    for node_type in ["Host", "User", "Process"]:
        data[node_type].num_nodes = nodes[node_type]["num_nodes"]
        data[node_type].x = torch.empty(
            (nodes[node_type]["num_nodes"], 0)
        )

    for edge_type, edge_data in data_dict["edges"].items():
        if len(edge_data["edge_index"][0]) > 0:
            data[edge_type].edge_index = torch.tensor(
                edge_data["edge_index"],
                dtype=torch.long
            )
        else:
            data[edge_type].edge_index = torch.empty(
                (2, 0),
                dtype=torch.long
            )

    return T.ToUndirected()(data)


train = load_graph(
    "data/processed/graphs_v1/train_data.pt"
)

val = load_graph(
    "data/processed/graphs_v1/val_data.pt"
)

edge_types = train.edge_types

num_classes = 15

y = train["Event"].y

counts = torch.bincount(
    y,
    minlength=num_classes
).float()

alpha = 1.0 / (counts + 1e-6)
alpha = alpha / alpha.sum() * num_classes

print()
print("========== CLASS WEIGHTS ==========")

for i in range(num_classes):
    print(
        f"Class {i:2d} | "
        f"Count: {int(counts[i])} | "
        f"Weight: {alpha[i].item():.8f}"
    )

print()
print("========== GRAPH ==========")
print("Train events:", train["Event"].num_nodes)
print("Validation events:", val["Event"].num_nodes)
print("Event features:", train["Event"].x.shape)
print("Edge types:", edge_types)

model = SOCFusionGAT(
    hidden_dim=64,
    num_heads=4,
    num_classes=num_classes,
    edge_types=edge_types,
    num_hosts=train["Host"].num_nodes,
    num_users=train["User"].num_nodes,
    num_processes=train["Process"].num_nodes
)

print()
print("========== MODEL ==========")
print(
    "Parameters:",
    sum(p.numel() for p in model.parameters())
)

model.eval()

with torch.no_grad():

    out, emb = model(
        train.x_dict,
        train.edge_index_dict
    )

    val_out, val_emb = model(
        val.x_dict,
        val.edge_index_dict
    )

print()
print("========== RAW OUTPUT ==========")

print("Train logits shape:", out.shape)
print("Val logits shape:", val_out.shape)

print(
    "Train logits min:",
    out.min().item()
)

print(
    "Train logits max:",
    out.max().item()
)

print(
    "Train logits mean:",
    out.mean().item()
)

print(
    "Train logits std:",
    out.std().item()
)

print()
print("========== SOFTMAX ==========")

train_prob = F.softmax(out, dim=-1)
val_prob = F.softmax(val_out, dim=-1)

print(
    "Train probability min:",
    train_prob.min().item()
)

print(
    "Train probability max:",
    train_prob.max().item()
)

print(
    "Val probability min:",
    val_prob.min().item()
)

print(
    "Val probability max:",
    val_prob.max().item()
)

print()
print("========== PREDICTIONS ==========")

train_pred = out.argmax(dim=-1)
val_pred = val_out.argmax(dim=-1)

print("Train predicted classes:")

for i in range(num_classes):
    print(
        f"  {i:2d}: "
        f"{(train_pred == i).sum().item()}"
    )

print()
print("Validation predicted classes:")

for i in range(num_classes):
    print(
        f"  {i:2d}: "
        f"{(val_pred == i).sum().item()}"
    )

print()
print("========== ACTUAL VALIDATION ==========")

for i in range(num_classes):
    print(
        f"  {i:2d}: "
        f"{(val['Event'].y == i).sum().item()}"
    )

criterion = FocalLoss(
    alpha=alpha,
    gamma=2.0
)

train_loss = criterion(
    out,
    train["Event"].y
)

val_loss = criterion(
    val_out,
    val["Event"].y
)

print()
print("========== LOSS DIAGNOSTIC ==========")

print(
    "Train loss:",
    repr(train_loss.item())
)

print(
    "Val loss:",
    repr(val_loss.item())
)

print(
    "Train loss finite:",
    torch.isfinite(train_loss).item()
)

print(
    "Val loss finite:",
    torch.isfinite(val_loss).item()
)

print()
print("========== DIAGNOSTIC COMPLETE ==========")
