import os
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, GATv2Conv
import pickle
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

class SOCFusionGATv6(nn.Module):
    def __init__(self, in_channels, hidden_dim, num_classes, edge_types, dropout=0.3):
        super().__init__()
        self.event_proj = nn.Sequential(
            nn.Linear(in_channels, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, hidden_dim),
            nn.LayerNorm(hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout)
        )
        self.host_emb = nn.Parameter(torch.randn(1, hidden_dim))
        self.user_emb = nn.Parameter(torch.randn(1, hidden_dim))
        self.process_emb = nn.Parameter(torch.randn(1, hidden_dim))
        self.edge_types = edge_types
        if edge_types:
            convs1 = {e: GATv2Conv(hidden_dim, hidden_dim//4, heads=4, add_self_loops=False) for e in edge_types}
            self.conv1 = HeteroConv(convs1, aggr='mean')
        else:
            self.conv1 = None
        self.classifier = nn.Linear(hidden_dim, num_classes)
        
    def forward(self, x_dict, edge_index_dict, return_emb=False):
        h_dict = {}
        h_dict['Event'] = self.event_proj(x_dict['Event'])
        if 'Host' in x_dict: h_dict['Host'] = self.host_emb.expand(x_dict['Host'].shape[0], -1)
        if 'User' in x_dict: h_dict['User'] = self.user_emb.expand(x_dict['User'].shape[0], -1)
        if 'Process' in x_dict: h_dict['Process'] = self.process_emb.expand(x_dict['Process'].shape[0], -1)
        if self.conv1 is not None:
            filtered_edge_index = {k: v for k, v in edge_index_dict.items() if k in self.edge_types}
            h_out = self.conv1(h_dict, filtered_edge_index)
            if 'Event' in h_out:
                h_dict['Event'] = h_dict['Event'] + F.relu(h_out['Event'])
        if return_emb: return h_dict['Event']
        return self.classifier(h_dict['Event'])

def load_graph(filepath):
    import torch_geometric.transforms as T
    with open(filepath, 'rb') as f:
        data_dict = pickle.load(f)
    data = HeteroData()
    nodes = data_dict['nodes']
    data['Event'].x = torch.tensor(nodes['Event']['x'], dtype=torch.float32)
    data['Event'].y = torch.tensor(nodes['Event']['y'], dtype=torch.long)
    data['Event'].num_nodes = nodes['Event']['num_nodes']
    data['Host'].num_nodes = nodes['Host']['num_nodes']
    data['Host'].x = torch.empty((nodes['Host']['num_nodes'], 0))
    data['User'].num_nodes = nodes['User']['num_nodes']
    data['User'].x = torch.empty((nodes['User']['num_nodes'], 0))
    data['Process'].num_nodes = nodes['Process']['num_nodes']
    data['Process'].x = torch.empty((nodes['Process']['num_nodes'], 0))
    for edge_type, edge_data in data_dict['edges'].items():
        if len(edge_data['edge_index'][0]) > 0:
            data[edge_type].edge_index = torch.tensor(edge_data['edge_index'], dtype=torch.long)
        else:
            data[edge_type].edge_index = torch.empty((2, 0), dtype=torch.long)
    return T.ToUndirected()(data)

def main():
    print("Starting Clean Inference Test...")
    GRAPH_PATH = "data/processed/graphs_v4/test_data.pt"
    MODEL_PATH = "data/processed/final_model/final_model.pth"
    CONFIG_PATH = "data/processed/final_model/model_config.json"
    
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
        
    print("Verifying model configuration...")
    assert config["architecture"] == "SOCFusionGATv6"
    assert config["in_channels"] == 102
    assert config["hidden_dim"] == 128
    assert config["num_classes"] == 12
    
    expected_edges = [
        ['Event', 'INVOLVES', 'Process'],
        ['Process', 'SPAWNED', 'Process'],
        ['Process', 'rev_INVOLVES', 'Event']
    ]
    # In json, they are stored as lists
    actual_edges = config["edge_types"]
    assert actual_edges == expected_edges
    print("Configuration verified.")
    
    data = load_graph(GRAPH_PATH)
    
    # tuple conversion for PyG
    edge_types = [tuple(e) for e in actual_edges]
    
    model = SOCFusionGATv6(config["in_channels"], config["hidden_dim"], config["num_classes"], edge_types)
    model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu'))
    
    print("Running frozen model in eval mode...")
    model.eval()
    
    with torch.no_grad():
        logits = model(data.x_dict, data.edge_index_dict)
        embeddings = model(data.x_dict, data.edge_index_dict, return_emb=True)
        probs = F.softmax(logits, dim=-1)
        
    print("Validating inference outputs...")
    assert not torch.isnan(data['Event'].x).any(), "NaN found in features"
    assert not torch.isinf(data['Event'].x).any(), "Inf found in features"
    
    assert not torch.isnan(logits).any(), "NaN found in logits"
    assert not torch.isinf(logits).any(), "Inf found in logits"
    
    assert not torch.isnan(embeddings).any(), "NaN found in embeddings"
    assert not torch.isinf(embeddings).any(), "Inf found in embeddings"
    
    assert logits.shape[1] == 12
    assert embeddings.shape[1] == 128
    
    preds = logits.argmax(dim=-1)
    assert (preds >= 0).all() and (preds < 12).all(), "Predictions out of class index bounds"
    
    assert (probs >= 0).all() and (probs <= 1).all(), "Confidence values out of [0,1] bounds"
    
    print("CLEAN INFERENCE VALIDATION PASSED.")

if __name__ == "__main__":
    main()
