import os
import torch
import torch.nn as nn
from torch_geometric.data import HeteroData
import torch_geometric.transforms as T
import pickle
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.models.gat_v4 import SOCFusionGATv4

def load_graph(filepath):
    print(f"Loading {filepath}...")
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
            
    data = T.ToUndirected()(data)
    return data

def main():
    OUT_DIR = "data/analysis/gat_v4"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    train_data = load_graph("data/processed/graphs_v2/train_data.pt")
    
    model = SOCFusionGATv4(
        hidden_dim=64, 
        num_heads=4, 
        num_classes=15, 
        edge_types=train_data.edge_types
    )
    
    validation_results = []
    
    # Verify model instantiates and HeteroConv uses mean aggregation
    aggr_conv1 = model.conv1.aggr
    aggr_conv2 = model.conv2.aggr
    
    validation_results.append(f"Model instantiated successfully: True")
    validation_results.append(f"conv1 aggr is 'mean': {aggr_conv1 == 'mean'}")
    validation_results.append(f"conv2 aggr is 'mean': {aggr_conv2 == 'mean'}")
    
    has_host_emb = hasattr(model, 'host_emb')
    has_host_type = hasattr(model, 'host_type_emb') and isinstance(model.host_type_emb, nn.Parameter)
    
    validation_results.append(f"Identity embeddings removed: {not has_host_emb}")
    validation_results.append(f"Shared Host type parameter exists: {has_host_type}")
    
    # Forward Pass
    out, emb = model(train_data.x_dict, train_data.edge_index_dict)
    validation_results.append(f"Forward pass successful. Output shape: {out.shape}")
    validation_results.append(f"Event Output classes: {out.size(-1)} (15 total, 12 supervised Track A)")
    
    # Backward Pass
    criterion = nn.CrossEntropyLoss()
    loss = criterion(out, train_data['Event'].y)
    
    # Finite Loss
    is_finite = not (torch.isnan(loss) or torch.isinf(loss))
    validation_results.append(f"Finite loss: {is_finite} ({loss.item():.4f})")
    
    loss.backward()
    
    # Finite Gradients
    finite_grads = True
    for p in model.parameters():
        if p.grad is not None:
            if torch.isnan(p.grad).any() or torch.isinf(p.grad).any():
                finite_grads = False
    validation_results.append(f"Finite gradients: {finite_grads}")
    
    md_content = "# Implementation Validation GAT V4\n\n"
    for res in validation_results:
        md_content += f"- {res}\n"
        
    passed = (aggr_conv1 == 'mean' and aggr_conv2 == 'mean' and not has_host_emb and has_host_type and is_finite and finite_grads)
    
    if passed:
        md_content += "\nSTATUS: PASSED. Proceed to training."
    else:
        md_content += "\nSTATUS: FAILED."
        
    with open(os.path.join(OUT_DIR, "implementation_validation.md"), "w") as f:
        f.write(md_content)
        
    print("Smoke test complete.")
    if not passed:
        sys.exit(1)

if __name__ == "__main__":
    main()
