import os
import random
import torch
import torch.nn as nn
import torch.nn.functional as F

from torch_geometric.nn import GATConv

# ============================================================
# CONFIGURATION
# ============================================================

GRAPH_FILE = "data/attack_graph.pt"
MODEL_FILE = "data/contrastive_relational_gat_encoder.pt"
EMBED_FILE = "data/contrastive_node_embeddings.pt"

SEED = 42

HIDDEN_DIM = 64
EMBED_DIM = 32

HEADS = 4

LR = 0.003
WEIGHT_DECAY = 1e-4

EPOCHS = 500

TEMPERATURE = 0.20

# ============================================================
# REPRODUCIBILITY
# ============================================================

random.seed(SEED)
torch.manual_seed(SEED)

if torch.cuda.is_available():
    torch.cuda.manual_seed_all(SEED)

device = torch.device(
    "cuda" if torch.cuda.is_available() else "cpu"
)

# ============================================================
# LOAD GRAPH
# ============================================================

data = torch.load(
    GRAPH_FILE,
    weights_only=False
)

data = data.to(device)

x = data.x.float()
edge_index = data.edge_index.long()
edge_type = data.edge_type.long()

num_nodes = data.num_nodes
num_edge_types = int(data.num_edge_types)

print()
print("========== LOADED GRAPH ==========")
print("Nodes      :", num_nodes)
print("Edges      :", edge_index.size(1))
print("Features   :", x.size(1))
print("Edge types :", num_edge_types)
print("Device     :", device)

# ============================================================
# RELATIONAL GAT
# ============================================================

class RelationalGAT(nn.Module):

    def __init__(
        self,
        in_dim,
        hidden_dim,
        embed_dim,
        num_edge_types,
        heads=4
    ):

        super().__init__()

        self.edge_embedding = nn.Embedding(
            num_edge_types,
            hidden_dim
        )

        self.gat1 = GATConv(
            in_channels=in_dim,
            out_channels=hidden_dim // heads,
            heads=heads,
            concat=True,
            dropout=0.10
        )

        self.gat2 = GATConv(
            in_channels=hidden_dim,
            out_channels=hidden_dim // heads,
            heads=heads,
            concat=True,
            dropout=0.10
        )

        self.projection = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.10),
            nn.Linear(hidden_dim, embed_dim)
        )

    def forward(
        self,
        x,
        edge_index,
        edge_type
    ):

        # ----------------------------------------------------
        # Edge-type representation
        # ----------------------------------------------------

        relation = self.edge_embedding(edge_type)

        # Aggregate relation information per destination node.
        relation_node = torch.zeros(
            x.size(0),
            relation.size(1),
            device=x.device
        )

        destination = edge_index[1]

        relation_node.index_add_(
            0,
            destination,
            relation
        )

        degree = torch.bincount(
            destination,
            minlength=x.size(0)
        ).float().to(x.device)

        degree = degree.clamp(min=1).unsqueeze(1)

        relation_node = relation_node / degree

        # ----------------------------------------------------
        # First GAT layer
        # ----------------------------------------------------

        h = self.gat1(
            x,
            edge_index
        )

        h = F.elu(h)

        # Add relational information
        h = h + relation_node

        h = F.dropout(
            h,
            p=0.10,
            training=self.training
        )

        # ----------------------------------------------------
        # Second GAT layer
        # ----------------------------------------------------

        h2 = self.gat2(
            h,
            edge_index
        )

        h2 = F.elu(h2)

        # Residual connection
        h = h + h2

        # ----------------------------------------------------
        # Projection head
        # ----------------------------------------------------

        z = self.projection(h)

        # Normalize embeddings
        z = F.normalize(
            z,
            p=2,
            dim=1
        )

        return z


# ============================================================
# MODEL
# ============================================================

model = RelationalGAT(
    in_dim=x.size(1),
    hidden_dim=HIDDEN_DIM,
    embed_dim=EMBED_DIM,
    num_edge_types=num_edge_types,
    heads=HEADS
).to(device)

optimizer = torch.optim.AdamW(
    model.parameters(),
    lr=LR,
    weight_decay=WEIGHT_DECAY
)

# ============================================================
# POSITIVE PAIRS
# ============================================================

# Nodes connected by an observed graph edge are positive
# structural pairs.

src = edge_index[0]
dst = edge_index[1]

positive_pairs = torch.stack(
    [src, dst],
    dim=1
)

# Remove duplicate pairs
positive_pairs = torch.unique(
    positive_pairs,
    dim=0
)

print()
print("========== CONTRASTIVE PAIRS ==========")
print(
    "Positive structural pairs :",
    positive_pairs.size(0)
)

# ============================================================
# CONTRASTIVE LOSS
# ============================================================

def contrastive_loss(
    z,
    positive_pairs,
    temperature
):

    # --------------------------------------------------------
    # Similarity matrix
    # --------------------------------------------------------

    similarity = torch.mm(
        z,
        z.t()
    ) / temperature

    # --------------------------------------------------------
    # Positive mask
    # --------------------------------------------------------

    positive_mask = torch.zeros_like(
        similarity,
        dtype=torch.bool
    )

    positive_mask[
        positive_pairs[:, 0],
        positive_pairs[:, 1]
    ] = True

    # Graph is directed, therefore also treat the reverse
    # direction as a positive structural relationship.

    positive_mask[
        positive_pairs[:, 1],
        positive_pairs[:, 0]
    ] = True

    # Self similarity must not participate.
    positive_mask.fill_diagonal_(False)

    # --------------------------------------------------------
    # For each node, use all connected nodes as positives.
    # --------------------------------------------------------

    losses = []

    for i in range(z.size(0)):

        positives = positive_mask[i]

        if positives.sum() == 0:
            continue

        logits = similarity[i].clone()

        # Remove self
        logits[i] = -1e9

        # ----------------------------------------------------
        # LogSumExp denominator
        # ----------------------------------------------------

        denominator = torch.logsumexp(
            logits,
            dim=0
        )

        positive_logits = logits[positives]

        # Average positive probability
        loss_i = (
            denominator
            - positive_logits.mean()
        )

        losses.append(loss_i)

    if not losses:

        return torch.tensor(
            0.0,
            device=z.device,
            requires_grad=True
        )

    return torch.stack(losses).mean()


# ============================================================
# TRAINING
# ============================================================

print()
print("========== STARTING CONTRASTIVE RELATIONAL GAT ==========")

best_loss = float("inf")
best_state = None

for epoch in range(1, EPOCHS + 1):

    model.train()

    optimizer.zero_grad()

    z = model(
        x,
        edge_index,
        edge_type
    )

    loss = contrastive_loss(
        z,
        positive_pairs,
        TEMPERATURE
    )

    loss.backward()

    torch.nn.utils.clip_grad_norm_(
        model.parameters(),
        max_norm=2.0
    )

    optimizer.step()

    current_loss = loss.item()

    if current_loss < best_loss:

        best_loss = current_loss

        best_state = {
            key: value.detach().cpu().clone()
            for key, value in model.state_dict().items()
        }

    if (
        epoch == 1
        or epoch % 25 == 0
        or epoch == EPOCHS
    ):

        print(
            f"Epoch {epoch:03d} | "
            f"Loss: {current_loss:.6f} | "
            f"Best: {best_loss:.6f}"
        )

# ============================================================
# RESTORE BEST MODEL
# ============================================================

if best_state is not None:

    model.load_state_dict(
        best_state
    )

# ============================================================
# GENERATE FINAL EMBEDDINGS
# ============================================================

print()
print("========== GENERATING EMBEDDINGS ==========")

model.eval()

with torch.no_grad():

    embeddings = model(
        x,
        edge_index,
        edge_type
    )

# ============================================================
# SAVE MODEL
# ============================================================

torch.save(
    {
        "model_state_dict": model.state_dict(),
        "input_dim": x.size(1),
        "hidden_dim": HIDDEN_DIM,
        "embedding_dim": EMBED_DIM,
        "num_edge_types": num_edge_types,
        "heads": HEADS
    },
    MODEL_FILE
)

torch.save(
    embeddings.cpu(),
    EMBED_FILE
)

# ============================================================
# BASIC VALIDATION
# ============================================================

print()
print("========== CONTRASTIVE RELATIONAL GAT COMPLETE ==========")

print(
    "Embedding shape :",
    tuple(embeddings.shape)
)

print(
    "Best loss       :",
    best_loss
)

print(
    "Model           :",
    MODEL_FILE
)

print(
    "Embeddings      :",
    EMBED_FILE
)

print(
    "NaN             :",
    torch.isnan(embeddings).any().item()
)

print(
    "Inf             :",
    torch.isinf(embeddings).any().item()
)

print()
print("Training complete.")
