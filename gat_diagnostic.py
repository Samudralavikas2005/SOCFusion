import torch
import torch.nn.functional as F
from collections import Counter

GRAPH_FILE = "data/attack_graph.pt"
EMBED_FILE = "data/contrastive_node_embeddings.pt"

data = torch.load(GRAPH_FILE, weights_only=False)
z = torch.load(EMBED_FILE, weights_only=False)

print("\n========== GAT EMBEDDING DIAGNOSTIC ==========")

print("Embedding shape :", tuple(z.shape))

# --------------------------------------------------
# 1. Basic statistics
# --------------------------------------------------

print("\n========== BASIC STATISTICS ==========")

print("Mean :", z.mean().item())
print("Std  :", z.std().item())
print("Min  :", z.min().item())
print("Max  :", z.max().item())

print("NaN  :", torch.isnan(z).any().item())
print("Inf  :", torch.isinf(z).any().item())

# --------------------------------------------------
# 2. Embedding norms
# --------------------------------------------------

norms = torch.norm(z, dim=1)

print("\n========== EMBEDDING NORMS ==========")

print("Mean norm :", norms.mean().item())
print("Std norm  :", norms.std().item())
print("Min norm  :", norms.min().item())
print("Max norm  :", norms.max().item())

# --------------------------------------------------
# 3. Pairwise cosine similarity
# --------------------------------------------------

z_norm = F.normalize(z, p=2, dim=1)

similarity = z_norm @ z_norm.T

# Remove self-similarity
mask = ~torch.eye(
    similarity.size(0),
    dtype=torch.bool
)

off_diag = similarity[mask]

print("\n========== PAIRWISE SIMILARITY ==========")

print("Mean similarity :", off_diag.mean().item())
print("Std similarity  :", off_diag.std().item())
print("Min similarity  :", off_diag.min().item())
print("Max similarity  :", off_diag.max().item())

# --------------------------------------------------
# 4. How many pairs are almost identical?
# --------------------------------------------------

for threshold in [0.99, 0.999, 0.9999]:

    count = (off_diag >= threshold).sum().item()

    print(
        f"Pairs >= {threshold}: {count}"
    )

# --------------------------------------------------
# 5. Unique / near-duplicate embeddings
# --------------------------------------------------

print("\n========== NEAR-DUPLICATE CHECK ==========")

high_similarity_pairs = []

n = z.size(0)

for i in range(n):
    for j in range(i + 1, n):

        sim = similarity[i, j].item()

        if sim >= 0.999:

            high_similarity_pairs.append(
                (i, j, sim)
            )

print(
    "Unique pairs with similarity >= 0.999:",
    len(high_similarity_pairs)
)

for i, j, sim in high_similarity_pairs[:20]:

    print(
        f"Node {i} <-> Node {j} : {sim:.6f}"
    )

# --------------------------------------------------
# 6. Check embedding variance by dimension
# --------------------------------------------------

dimension_std = z.std(dim=0)

print("\n========== DIMENSION VARIANCE ==========")

print("Mean dimension std :", dimension_std.mean().item())
print("Min dimension std  :", dimension_std.min().item())
print("Max dimension std  :", dimension_std.max().item())

dead_dimensions = (
    dimension_std < 1e-4
).sum().item()

print(
    "Nearly constant dimensions:",
    dead_dimensions,
    "/",
    z.size(1)
)

# --------------------------------------------------
# 7. Node type distribution
# --------------------------------------------------

if hasattr(data, "node_type"):

    print("\n========== NODE TYPE DISTRIBUTION ==========")

    counts = Counter(
        data.node_type.tolist()
    )

    for node_type, count in sorted(counts.items()):

        print(
            f"Node type {node_type}: {count}"
        )

# --------------------------------------------------
# 8. Graph structure
# --------------------------------------------------

print("\n========== GRAPH ==========")

print("Nodes :", data.num_nodes)
print("Edges :", data.edge_index.size(1))

if hasattr(data, "edge_type"):

    edge_counts = Counter(
        data.edge_type.tolist()
    )

    print("\nEdge type counts:")

    for edge_type, count in sorted(
        edge_counts.items()
    ):

        print(
            f"Edge type {edge_type}: {count}"
        )

print("\n========== DIAGNOSTIC COMPLETE ==========")
