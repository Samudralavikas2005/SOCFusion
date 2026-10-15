import pickle

graph_path = "data/processed/graphs_final_norm/test_data.pt"

print("Loading raw graph from:", graph_path)
with open(graph_path, "rb") as f:
    graph = pickle.load(f)

print("\n" + "=" * 60)
print("RAW GNN HETEROGENEOUS GRAPH STRUCTURE")
print("=" * 60)

print("\n--- Node Types & Counts ---")
for ntype, ndata in graph["nodes"].items():
    num_nodes = ndata.get("num_nodes", 0)
    print(f"  - Node Type: {ntype:10s} | Count: {num_nodes:,} nodes")

print("\n--- Edge Types & Edge Counts ---")
for etype, edata in graph["edges"].items():
    edge_index = edata.get("edge_index", [[], []])
    num_edges = len(edge_index[0]) if len(edge_index) > 0 else 0
    src_type, rel, dst_type = etype
    print(f"  - Relation: ({src_type:7s} --[{rel:10s}]--> {dst_type:7s}) | Count: {num_edges:,} edges")

print("\n" + "=" * 60)
print("Graph diagnostic inspection complete.")
print("=" * 60)
