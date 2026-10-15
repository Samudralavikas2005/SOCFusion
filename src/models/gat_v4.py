import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import HeteroConv, GATv2Conv, Linear

class SOCFusionGATv4(nn.Module):
    def __init__(self, hidden_dim=64, num_heads=4, num_classes=15, edge_types=None):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads
        self.edge_types = edge_types
        
        # Initial Projections
        self.event_proj = Linear(17, hidden_dim)
        
        # Type-Level Entity Representations (NO identity memorization)
        self.host_type_emb = nn.Parameter(torch.Tensor(1, hidden_dim))
        self.user_type_emb = nn.Parameter(torch.Tensor(1, hidden_dim))
        self.process_type_emb = nn.Parameter(torch.Tensor(1, hidden_dim))
        
        nn.init.xavier_uniform_(self.host_type_emb)
        nn.init.xavier_uniform_(self.user_type_emb)
        nn.init.xavier_uniform_(self.process_type_emb)
        
        # Layer 1
        convs1 = {
            edge: GATv2Conv(hidden_dim, hidden_dim // num_heads, heads=num_heads, add_self_loops=False)
            for edge in edge_types
        }
        # V4 CHANGE: aggr='mean' instead of 'sum'
        self.conv1 = HeteroConv(convs1, aggr='mean')
        
        # Layer 2
        convs2 = {
            edge: GATv2Conv(hidden_dim, hidden_dim // num_heads, heads=num_heads, add_self_loops=False)
            for edge in edge_types
        }
        # V4 CHANGE: aggr='mean' instead of 'sum'
        self.conv2 = HeteroConv(convs2, aggr='mean')
        
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
        
        # Assign shared type-level representations independent of identity
        if 'Host' in x_dict:
            num_h = x_dict['Host'].shape[0]
            h_dict['Host'] = self.host_type_emb.expand(num_h, -1)
        
        if 'User' in x_dict:
            num_u = x_dict['User'].shape[0]
            h_dict['User'] = self.user_type_emb.expand(num_u, -1)
            
        if 'Process' in x_dict:
            num_p = x_dict['Process'].shape[0]
            h_dict['Process'] = self.process_type_emb.expand(num_p, -1)

        h_dict_out = self.conv1(h_dict, edge_index_dict)
        h_dict = {k: F.leaky_relu(v) for k, v in h_dict_out.items()}
        
        if 'Event' in h_dict_out:
            h_dict['Event'] = h_dict['Event'] + self.event_proj(x_dict['Event'])
            
        h_dict_out = self.conv2(h_dict, edge_index_dict)
        h_dict = {k: F.leaky_relu(v) for k, v in h_dict_out.items()}

        event_embeddings = h_dict['Event']
        out = self.classifier(event_embeddings)
        
        return out, event_embeddings
