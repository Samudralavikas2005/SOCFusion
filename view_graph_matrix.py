import pickle

graph_path = "data/processed/graphs_final_norm/test_data.pt"

with open(graph_path, "rb") as f:
    graph = pickle.load(f)

print("\n" + "=" * 70)
print("INSIDE THE PHYSICAL GRAPH FILE: data/processed/graphs_final_norm/test_data.pt")
print("=" * 70)

# 1. Event Node Feature Vectors & Labels
event_x = graph["nodes"]["Event"].get("x")
event_y = graph["nodes"]["Event"].get("y")

num_events = len(event_x)
num_features = len(event_x[0]) if num_events > 0 else 0

print("\n1. EVENT NODE FEATURES & LABELS:")
print(f"   - Feature Matrix size (X)  : [{num_events:,} events x {num_features} features per event]")
print(f"   - Label Vector size (Y)    : [{len(event_y):,} ground truth labels]")
print(f"   - Sample Feature Vector for Event 0 (first 5 features): {event_x[0][:5]}")
print(f"   - Ground Truth Class Label for Event 0               : {event_y[0]}")

# 2. PRECEDES Adjacency Matrix (Edges)
precedes_edges = graph["edges"][("Event", "PRECEDES", "Event")]["edge_index"]
num_precedes = len(precedes_edges[0])

print("\n2. TEMPORAL PRECEDES EDGES ADJACENCY MATRIX:")
print(f"   - Total PRECEDES edges: {num_precedes:,}")
print("   - Sample Edge Index Pairs (Source Event Node -> Destination Event Node):")

for i in range(min(10, num_precedes)):
    src_node = precedes_edges[0][i]
    dst_node = precedes_edges[1][i]
    print(f"       Edge {i+1:2d}: Event Node {src_node:6d}  ====[ PRECEDES ]====>  Event Node {dst_node:6d}")

print("\n" + "=" * 70)
print("This binary file (X feature vectors + edge_index pairs) IS the actual Graph Data.")
print("=" * 70)
