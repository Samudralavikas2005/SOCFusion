import csv
import torch
import torch.nn.functional as F

NODE_FILE = "data/attack_nodes.csv"
EMBED_FILE = "data/relational_node_embeddings.pt"

embeddings = torch.load(
    EMBED_FILE,
    weights_only=False
)

node_ids = []

with open(NODE_FILE, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        node_ids.append(row["node_id"])

node_to_idx = {
    node_id: i
    for i, node_id in enumerate(node_ids)
}

targets = [
    "process:348",
    "process:2580",
    "process:3236"
]

print()
print("========== RELATIONAL GAT ATTACK CHAIN ==========")

for i in range(len(targets)):

    for j in range(i + 1, len(targets)):

        a = embeddings[
            node_to_idx[targets[i]]
        ]

        b = embeddings[
            node_to_idx[targets[j]]
        ]

        similarity = F.cosine_similarity(
            a.unsqueeze(0),
            b.unsqueeze(0)
        ).item()

        print(
            f"{targets[i]} <-> "
            f"{targets[j]}: "
            f"{similarity:.4f}"
        )

print()
print("========== NEAREST NODES ==========")

for target in targets:

    idx = node_to_idx[target]

    target_embedding = embeddings[idx]

    similarities = F.cosine_similarity(
        target_embedding.unsqueeze(0),
        embeddings
    ).squeeze(0)

    values, indices = torch.topk(
        similarities,
        k=11
    )

    print()
    print("Target:", target)

    count = 0

    for value, node_idx in zip(values, indices):

        node = node_ids[node_idx.item()]

        if node == target:
            continue

        print(
            f"  {node} "
            f"similarity={value.item():.4f}"
        )

        count += 1

        if count >= 10:
            break

print()
print("========== STATISTICS ==========")

print("Shape:", tuple(embeddings.shape))
print("Mean:", embeddings.mean().item())
print("Std:", embeddings.std().item())
print("Min:", embeddings.min().item())
print("Max:", embeddings.max().item())

print()
print(
    "NaN:",
    torch.isnan(embeddings).any().item()
)

print(
    "Inf:",
    torch.isinf(embeddings).any().item()
)

print()
print("========== COMPLETE ==========")
