import csv
import torch
import torch.nn.functional as F

NODE_FILE = "data/attack_nodes.csv"
EMBED_FILE = "data/contrastive_node_embeddings.pt"

# ------------------------------------------------------------
# Load embeddings
# ------------------------------------------------------------

z = torch.load(
    EMBED_FILE,
    weights_only=False
)

z = F.normalize(z, p=2, dim=1)

# ------------------------------------------------------------
# Load node order
# ------------------------------------------------------------

node_ids = []

with open(NODE_FILE, newline="") as f:

    reader = csv.DictReader(f)

    for row in reader:
        node_ids.append(row["node_id"])

node_to_idx = {
    node_id: i
    for i, node_id in enumerate(node_ids)
}

# ------------------------------------------------------------
# Known attack chain
# ------------------------------------------------------------

chain = [
    "process:348",
    "process:2580",
    "process:3236"
]

print()
print("========== CONTRASTIVE EMBEDDING EVALUATION ==========")

print()
print("Known attack chain:")

for node in chain:

    print(
        node,
        "Index:",
        node_to_idx[node]
    )

# ------------------------------------------------------------
# Chain similarity
# ------------------------------------------------------------

print()
print("========== ATTACK CHAIN SIMILARITY ==========")

for i in range(len(chain)):

    for j in range(i + 1, len(chain)):

        a = node_to_idx[chain[i]]
        b = node_to_idx[chain[j]]

        sim = torch.dot(
            z[a],
            z[b]
        ).item()

        print(
            f"{chain[i]} <-> {chain[j]}: "
            f"{sim:.4f}"
        )

# ------------------------------------------------------------
# Compare attack nodes with unrelated processes
# ------------------------------------------------------------

process_nodes = [
    node
    for node in node_ids
    if node.startswith("process:")
]

print()
print("========== ATTACK VS OTHER PROCESSES ==========")

for target in chain:

    target_idx = node_to_idx[target]

    results = []

    for node in process_nodes:

        if node == target:
            continue

        idx = node_to_idx[node]

        sim = torch.dot(
            z[target_idx],
            z[idx]
        ).item()

        results.append(
            (node, sim)
        )

    results.sort(
        key=lambda x: x[1],
        reverse=True
    )

    print()
    print("Target:", target)

    for node, sim in results[:10]:

        print(
            f"  {node}: {sim:.4f}"
        )

# ------------------------------------------------------------
# Positive structural relationships
# ------------------------------------------------------------

print()
print("========== KNOWN PROCESS RELATIONS ==========")

known_relations = [
    ("process:348", "process:2580"),
    ("process:2580", "process:3236")
]

for source, target in known_relations:

    a = node_to_idx[source]
    b = node_to_idx[target]

    sim = torch.dot(
        z[a],
        z[b]
    ).item()

    print(
        f"{source} -> {target}: "
        f"{sim:.4f}"
    )

# ------------------------------------------------------------
# Statistics
# ------------------------------------------------------------

print()
print("========== EMBEDDING STATISTICS ==========")

similarity = z @ z.T

mask = ~torch.eye(
    similarity.size(0),
    dtype=torch.bool
)

off_diag = similarity[mask]

print(
    "Mean pairwise similarity:",
    off_diag.mean().item()
)

print(
    "Std pairwise similarity:",
    off_diag.std().item()
)

print(
    "Minimum:",
    off_diag.min().item()
)

print(
    "Maximum:",
    off_diag.max().item()
)

print()
print("========== EVALUATION COMPLETE ==========")
