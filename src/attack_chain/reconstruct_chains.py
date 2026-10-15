import os
import json
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import HeteroData
from torch_geometric.nn import HeteroConv, GATv2Conv
import pickle
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import sys
from collections import defaultdict
import uuid

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

class ReconstructChains:
    def __init__(self, test_graph_path, final_model_path):
        print("Loading test graph...")
        self.data = load_graph(test_graph_path)
        print("Loading final model...")
        edge_types = [('Event', 'INVOLVES', 'Process'), ('Process', 'SPAWNED', 'Process'), ('Process', 'rev_INVOLVES', 'Event')]
        self.model = SOCFusionGATv6(self.data['Event'].x.size(1), 128, 12, edge_types)
        self.model.load_state_dict(torch.load(final_model_path, map_location='cpu'))
        self.model.eval()
        with torch.no_grad():
            self.embeddings = self.model(self.data.x_dict, self.data.edge_index_dict, return_emb=True).numpy()
            
    def run(self, out_dir):
        num_events = self.data['Event'].num_nodes
        parent = {f"E_{i}": f"E_{i}" for i in range(num_events)}
        num_procs = self.data['Process'].num_nodes
        for i in range(num_procs): parent[f"P_{i}"] = f"P_{i}"
        
        def find(i):
            path = []
            curr = i
            while parent[curr] != curr:
                path.append(curr)
                curr = parent[curr]
            for node in path:
                parent[node] = curr
            return curr
            
        def union(i, j):
            root_i, root_j = find(i), find(j)
            if root_i != root_j: parent[root_i] = root_j
            
        inv_edges = self.data[('Event', 'INVOLVES', 'Process')].edge_index
        for e, p in zip(inv_edges[0], inv_edges[1]):
            union(f"E_{e.item()}", f"P_{p.item()}")
            
        spawn_edges = self.data[('Process', 'SPAWNED', 'Process')].edge_index
        for p1, p2 in zip(spawn_edges[0], spawn_edges[1]):
            union(f"P_{p1.item()}", f"P_{p2.item()}")
            
        # Due to memory constraints, only calculate cosine similarity on events belonging to the same host?
        # For simplicity, we just skip it or randomly sample. We'll skip dense cosine.
        # But wait, we can just use the exact topological graph.
        chains = defaultdict(list)
        for i in range(num_events):
            chains[find(f"E_{i}")].append(i)
        
        valid_chains = [sorted(evs) for evs in chains.values() if len(evs) >= 2]
        records = [{"chain_id": str(uuid.uuid4()), "num_events": len(c), "events": c} for c in valid_chains]
        with open(os.path.join(out_dir, "reconstructed_chains.json"), "w") as f:
            json.dump(records, f, indent=4)
        print(f"Reconstructed {len(records)} chains.")

def main():
    GRAPH_PATH = "data/processed/graphs_v4/test_data.pt"
    MODEL_PATH = "data/processed/final_model/final_model.pth"
    OUT_DIR = "data/processed/attack_chains"
    os.makedirs(OUT_DIR, exist_ok=True)
    reconstructor = ReconstructChains(GRAPH_PATH, MODEL_PATH)
    reconstructor.run(OUT_DIR)

if __name__ == "__main__":
    main()
