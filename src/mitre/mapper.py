import os
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, GATv2Conv
import pickle
import numpy as np
import pandas as pd
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
    GRAPH_PATH = "data/processed/graphs_v4/test_data.pt"
    MODEL_PATH = "data/processed/final_model/final_model.pth"
    CHAINS_PATH = "data/processed/attack_chains/reconstructed_chains.json"
    CLASS_MAP = "data/processed/final_model/class_mapping.json"
    OUT_DIR = "data/analysis/mitre_mapping"
    
    os.makedirs(OUT_DIR, exist_ok=True)
    
    with open(CLASS_MAP, 'r') as f:
        idx_to_str = json.load(f)
        
    with open(CHAINS_PATH, 'r') as f:
        chains = json.load(f)
        
    data = load_graph(GRAPH_PATH)
    edge_types = [('Event', 'INVOLVES', 'Process'), ('Process', 'SPAWNED', 'Process'), ('Process', 'rev_INVOLVES', 'Event')]
    model = SOCFusionGATv6(data['Event'].x.size(1), 128, 12, edge_types)
    model.load_state_dict(torch.load(MODEL_PATH, map_location='cpu'))
    model.eval()
    
    with torch.no_grad():
        logits = model(data.x_dict, data.edge_index_dict)
        probs = F.softmax(logits, dim=-1).numpy()
        
    results = []
    
    # We don't have true labels for the chains since it's unsupervised chain reconstruction
    # But we can get the majority true label just for comparison if we want
    y_true_all = data['Event'].y.numpy()
    # Note: data['Event'].y contains labels 0-14. Our model only outputs 0-11 for Track A.
    # The actual true label might be out of bounds, so we just log it as an integer or map it.
    
    # Re-load full map to map y_true_all to string
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        full_map = json.load(f)
    orig_map = {v: k for k, v in full_map.items()}
    
    for c in chains:
        events = c['events']
        chain_probs = probs[events] # shape (N, 12)
        avg_probs = chain_probs.mean(axis=0)
        pred_idx = avg_probs.argmax()
        conf = avg_probs[pred_idx]
        pred_tech = idx_to_str[str(pred_idx)]
        
        # majority true label
        chain_trues = y_true_all[events]
        unique, counts = np.unique(chain_trues, return_counts=True)
        majority_true_idx = unique[counts.argmax()]
        if majority_true_idx == -1:
            true_tech = "Benign"
        else:
            true_tech = orig_map.get(majority_true_idx, "Unknown")
            
        results.append({
            "chain_id": c['chain_id'],
            "num_events": c['num_events'],
            "predicted_technique": pred_tech,
            "confidence": float(conf),
            "true_technique": true_tech
        })
        
    df = pd.DataFrame(results)
    df.to_csv(os.path.join(OUT_DIR, "mapping_examples.csv"), index=False)
    
    print(f"Mapped {len(results)} attack chains.")
    with open(os.path.join(OUT_DIR, "mitre_mappings.json"), "w") as f:
        json.dump(results, f, indent=4)

if __name__ == "__main__":
    main()
