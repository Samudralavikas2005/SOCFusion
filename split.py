import os
import pickle
import json
import numpy as np
from collections import defaultdict

BASE = "data/processed/graphs_v1"
OUT = "data/processed/graphs_final"

os.makedirs(OUT, exist_ok=True)

with open(f"{BASE}/train_data.pt", "rb") as f:
    train = pickle.load(f)

with open(f"{BASE}/val_data.pt", "rb") as f:
    val = pickle.load(f)

with open(f"{BASE}/test_data.pt", "rb") as f:
    test = pickle.load(f)

# Combine ALL existing events.
# These are all from the same GitHub-derived processed dataset.
datasets = [train, val, test]

X = []
Y = []

for d in datasets:
    X.extend(d["nodes"]["Event"]["x"])
    Y.extend(d["nodes"]["Event"]["y"])

X = np.asarray(X, dtype=np.float32)
Y = np.asarray(Y, dtype=np.int64)

print("========== COMBINED DATA ==========")
print("Events:", len(Y))
print("Features:", X.shape)

rng = np.random.default_rng(42)

# Stratified split:
# 70% train, 15% validation, 15% test
indices_by_class = defaultdict(list)

for i, label in enumerate(Y):
    indices_by_class[int(label)].append(i)

train_idx = []
val_idx = []
test_idx = []

for label, indices in sorted(indices_by_class.items()):
    indices = np.asarray(indices)
    rng.shuffle(indices)

    n = len(indices)

    if n == 1:
        train_idx.extend(indices)
    elif n == 2:
        train_idx.extend(indices[:1])
        test_idx.extend(indices[1:])
    else:
        n_train = max(1, int(n * 0.70))
        n_val = max(1, int(n * 0.15))

        # Ensure remaining examples go to test
        n_test = n - n_train - n_val

        if n_test < 1:
            n_test = 1
            n_train -= 1

        train_idx.extend(indices[:n_train])
        val_idx.extend(indices[n_train:n_train+n_val])
        test_idx.extend(indices[n_train+n_val:])

def make_graph(indices):
    indices = np.asarray(indices)

    return {
        "nodes": {
            "Event": {
                "x": X[indices].tolist(),
                "y": Y[indices].tolist(),
                "num_nodes": len(indices)
            },
            "Host": {"num_nodes": 0},
            "User": {"num_nodes": 0},
            "Process": {"num_nodes": 0}
        },
        "edges": {}
    }

splits = {
    "train": train_idx,
    "val": val_idx,
    "test": test_idx
}

print()
print("========== FINAL SPLIT ==========")

for name, indices in splits.items():
    graph = make_graph(indices)

    with open(f"{OUT}/{name}_data.pt", "wb") as f:
        pickle.dump(graph, f)

    labels, counts = np.unique(Y[indices], return_counts=True)

    print(f"\n{name.upper()}")
    print("Events:", len(indices))

    for label, count in zip(labels, counts):
        print(f"  class {label:2d}: {count}")

with open(f"{BASE}/label_mapping.json") as f:
    labels = json.load(f)

with open(f"{OUT}/label_mapping.json", "w") as f:
    json.dump(labels, f, indent=2)

print()
print("========== COMPLETE ==========")
print("Output:", OUT)
