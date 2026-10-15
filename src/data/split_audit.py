import os
import torch
import json
import csv
import pickle
import numpy as np
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T

OUT_DIR = "data/analysis/split_audit"
os.makedirs(OUT_DIR, exist_ok=True)

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
    
    for edge_type, edge_data in data_dict['edges'].items():
        if edge_type == ('Event', 'RUNS_ON', 'Host'):
            if len(edge_data['edge_index'][0]) > 0:
                data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
            else:
                data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
            
    return data

train_data = load_graph("data/processed/graphs_v1/train_data.pt")
val_data = load_graph("data/processed/graphs_v1/val_data.pt")
test_data = load_graph("data/processed/graphs_v1/test_data.pt")

with open("data/processed/graphs_v1/label_mapping.json", "r") as f:
    label_map = json.load(f)

# Reverse label map
idx_to_label = {v: k for k, v in label_map.items()}
num_classes = len(idx_to_label)

splits = [
    ("train", train_data),
    ("val", val_data),
    ("test", test_data)
]

host_offset = 0
event_to_host_global = {}
host_to_split = {}
host_to_techniques = {}

class_by_split = {i: {"train": 0, "val": 0, "test": 0, "technique": idx_to_label[i]} for i in range(num_classes)}
host_by_split = []

for split_name, data in splits:
    y = data['Event'].y.numpy()
    num_events = len(y)
    num_hosts = data['Host'].num_nodes
    
    for h in range(num_hosts):
        global_h = f"{split_name}_{h}"
        host_to_split[global_h] = split_name
        host_to_techniques[global_h] = set()
        host_by_split.append({"host_id": global_h, "split": split_name, "num_events": 0})
        
    edges = data[('Event', 'RUNS_ON', 'Host')].edge_index.numpy()
    # edge[0] is Event, edge[1] is Host
    event_hosts = {}
    for ev_idx, host_idx in zip(edges[0], edges[1]):
        global_h = f"{split_name}_{host_idx}"
        event_hosts[ev_idx] = global_h
        
    for ev_idx in range(num_events):
        cls = y[ev_idx]
        class_by_split[cls][split_name] += 1
        
        if ev_idx in event_hosts:
            global_h = event_hosts[ev_idx]
            host_to_techniques[global_h].add(cls)
            # Find the host in host_by_split and increment num_events
            for h_dict in host_by_split:
                if h_dict["host_id"] == global_h:
                    h_dict["num_events"] += 1
                    break
                    
with open(os.path.join(OUT_DIR, "class_by_split.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["class_idx", "technique", "train", "val", "test"])
    writer.writeheader()
    for i in range(num_classes):
        row = class_by_split[i].copy()
        row["class_idx"] = i
        writer.writerow(row)

with open(os.path.join(OUT_DIR, "host_by_split.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["host_id", "split", "num_events"])
    writer.writeheader()
    writer.writerows(host_by_split)

# Technique host distribution
technique_hosts = {i: [] for i in range(num_classes)}
for h, techs in host_to_techniques.items():
    for t in techs:
        technique_hosts[t].append(h)

tech_host_dist = []
for i in range(num_classes):
    tech_host_dist.append({
        "class_idx": i,
        "technique": idx_to_label[i],
        "num_distinct_hosts": len(technique_hosts[i]),
        "hosts": ";".join(technique_hosts[i])
    })

with open(os.path.join(OUT_DIR, "technique_host_distribution.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["class_idx", "technique", "num_distinct_hosts", "hosts"])
    writer.writeheader()
    writer.writerows(tech_host_dist)

# technique_split_coverage
tech_coverage = []
for i in range(num_classes):
    c = class_by_split[i]
    tech_coverage.append({
        "class_idx": i,
        "technique": idx_to_label[i],
        "zero_train": c["train"] == 0,
        "zero_val": c["val"] == 0,
        "zero_test": c["test"] == 0,
        "is_test_only": (c["train"] == 0 and c["val"] == 0 and c["test"] > 0)
    })

with open(os.path.join(OUT_DIR, "technique_split_coverage.csv"), "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["class_idx", "technique", "zero_train", "zero_val", "zero_test", "is_test_only"])
    writer.writeheader()
    writer.writerows(tech_coverage)

# host_technique_matrix
host_matrix = []
for h, techs in host_to_techniques.items():
    row = {"host_id": h, "split": host_to_split[h]}
    for i in range(num_classes):
        row[f"has_class_{i}"] = (i in techs)
    host_matrix.append(row)

with open(os.path.join(OUT_DIR, "host_technique_matrix.csv"), "w", newline="") as f:
    fieldnames = ["host_id", "split"] + [f"has_class_{i}" for i in range(num_classes)]
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(host_matrix)
    
print("Audit data generated successfully.")
