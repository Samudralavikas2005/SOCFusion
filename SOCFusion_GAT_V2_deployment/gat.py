import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, GATv2Conv, Linear


class SOCFusionGAT(nn.Module):

    def __init__(
        self,
        hidden_dim=64,
        num_heads=4,
        num_classes=15,
        edge_types=None,
        num_hosts=0,
        num_users=0,
        num_processes=0
    ):
        super().__init__()

        self.hidden_dim = hidden_dim
        self.num_heads = num_heads

        # Event feature projection
        self.event_proj = Linear(17, hidden_dim)

        # Learnable entity embeddings
        self.host_emb = nn.Embedding(
            max(1, num_hosts), hidden_dim
        )

        self.user_emb = nn.Embedding(
            max(1, num_users), hidden_dim
        )

        self.process_emb = nn.Embedding(
            max(1, num_processes), hidden_dim
        )

        # ==================================================
        # GAT LAYER 1
        # ==================================================

        convs1 = {}

        for edge in edge_types:
            convs1[edge] = GATv2Conv(
                hidden_dim,
                hidden_dim // num_heads,
                heads=num_heads,
                concat=True,
                dropout=0.2,
                add_self_loops=False
            )

        self.conv1 = HeteroConv(
            convs1,
            aggr="sum"
        )

        self.norm1 = nn.ModuleDict({
            "Event": nn.LayerNorm(hidden_dim),
            "Host": nn.LayerNorm(hidden_dim),
            "User": nn.LayerNorm(hidden_dim),
            "Process": nn.LayerNorm(hidden_dim)
        })

        # ==================================================
        # GAT LAYER 2
        # ==================================================

        convs2 = {}

        for edge in edge_types:
            convs2[edge] = GATv2Conv(
                hidden_dim,
                hidden_dim // num_heads,
                heads=num_heads,
                concat=True,
                dropout=0.2,
                add_self_loops=False
            )

        self.conv2 = HeteroConv(
            convs2,
            aggr="sum"
        )

        self.norm2 = nn.ModuleDict({
            "Event": nn.LayerNorm(hidden_dim),
            "Host": nn.LayerNorm(hidden_dim),
            "User": nn.LayerNorm(hidden_dim),
            "Process": nn.LayerNorm(hidden_dim)
        })

        # ==================================================
        # CLASSIFIER
        # ==================================================

        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x_dict, edge_index_dict):

        h = {}

        # Initial event representation
        h["Event"] = self.event_proj(x_dict["Event"])

        # Entity embeddings
        if "Host" in x_dict:
            n = x_dict["Host"].shape[0]
            h["Host"] = self.host_emb(
                torch.arange(
                    n,
                    device=x_dict["Event"].device
                )
            )

        if "User" in x_dict:
            n = x_dict["User"].shape[0]
            h["User"] = self.user_emb(
                torch.arange(
                    n,
                    device=x_dict["Event"].device
                )
            )

        if "Process" in x_dict:
            n = x_dict["Process"].shape[0]
            h["Process"] = self.process_emb(
                torch.arange(
                    n,
                    device=x_dict["Event"].device
                )
            )

        # ==================================================
        # GAT BLOCK 1 + RESIDUAL
        # ==================================================

        residual = h["Event"]

        out = self.conv1(h, edge_index_dict)

        h = {
            k: F.elu(v)
            for k, v in out.items()
        }

        for k in h:
            if k in self.norm1:
                h[k] = self.norm1[k](h[k])

        h["Event"] = h["Event"] + residual

        # ==================================================
        # GAT BLOCK 2 + RESIDUAL
        # ==================================================

        residual = h["Event"]

        out = self.conv2(h, edge_index_dict)

        h = {
            k: F.elu(v)
            for k, v in out.items()
        }

        for k in h:
            if k in self.norm2:
                h[k] = self.norm2[k](h[k])

        h["Event"] = h["Event"] + residual

        # ==================================================
        # CLASSIFICATION
        # ==================================================

        event_embeddings = h["Event"]

        logits = self.classifier(
            event_embeddings
        )

        return logits, event_embeddings
