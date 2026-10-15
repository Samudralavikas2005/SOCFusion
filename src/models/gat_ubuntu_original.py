import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, GATv2Conv, Linear

class SOCFusionGAT(nn.Module):
    def __init__(self, hidden_dim=64, num_heads=4, num_classes=15, edge_types=None, num_hosts=0, num_users=0, num_processes=0):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.edge_types = edge_types
        
        # Initial Projections
        self.event_proj = Linear(17, hidden_dim)
        
        # Entity Embeddings
        self.host_emb = nn.Embedding(max(1, num_hosts), hidden_dim)
        self.user_emb = nn.Embedding(max(1, num_users), hidden_dim)
        self.process_emb = nn.Embedding(max(1, num_processes), hidden_dim)
        
        # Layer 1
        convs1 = {
            edge: GATv2Conv(hidden_dim, hidden_dim // num_heads, heads=num_heads, add_self_loops=False)
            for edge in edge_types
        }
        self.conv1 = HeteroConv(convs1, aggr='sum')
        
        # Layer 2
        convs2 = {
            edge: GATv2Conv(hidden_dim, hidden_dim // num_heads, heads=num_heads, add_self_loops=False)
            for edge in edge_types
        }
        self.conv2 = HeteroConv(convs2, aggr='sum')
        
        # Classifier
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim),
            nn.ELU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, num_classes)
        )

    def forward(self, x_dict, edge_index_dict):
        h_dict = {}
        h_dict['Event'] = self.event_proj(x_dict['Event'])
        if 'Host' in x_dict:
            num_h = x_dict['Host'].shape[0] if x_dict['Host'].numel() > 0 else self.host_emb.num_embeddings
            h_dict['Host'] = self.host_emb(torch.arange(num_h, device=x_dict['Event'].device))
        
        if 'User' in x_dict:
            num_u = x_dict['User'].shape[0] if x_dict['User'].numel() > 0 else self.user_emb.num_embeddings
            h_dict['User'] = self.user_emb(torch.arange(num_u, device=x_dict['Event'].device))
            
        if 'Process' in x_dict:
            num_p = x_dict['Process'].shape[0] if x_dict['Process'].numel() > 0 else self.process_emb.num_embeddings
            h_dict['Process'] = self.process_emb(torch.arange(num_p, device=x_dict['Event'].device))

        h_dict_out = self.conv1(h_dict, edge_index_dict)
        h_dict = {k: F.leaky_relu(v) for k, v in h_dict_out.items()}
        
        if 'Event' in h_dict_out:
            h_dict['Event'] = h_dict['Event'] + self.event_proj(x_dict['Event'])
            
        h_dict_out = self.conv2(h_dict, edge_index_dict)
        h_dict = {k: F.leaky_relu(v) for k, v in h_dict_out.items()}

        event_embeddings = h_dict['Event']
        out = self.classifier(event_embeddings)
        
        return out, event_embeddings
