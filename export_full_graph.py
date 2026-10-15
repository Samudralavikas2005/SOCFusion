import pickle
import csv
import os

graph_path = "data/processed/graphs_final_norm/test_data.pt"
output_csv = "data/processed/full_graph_edges.csv"

print(f"Loading complete graph from: {graph_path}")
with open(graph_path, "rb") as f:
    graph = pickle.load(f)

edges_dict = graph["edges"]

os.makedirs(os.path.dirname(output_csv), exist_ok=True)

print("Exporting ALL edges to CSV:", output_csv)

total_edges_exported = 0

with open(output_csv, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["edge_type", "source_node_type", "source_node_id", "relation", "target_node_type", "target_node_id"])

    for (src_type, rel, dst_type), edata in edges_dict.items():
        edge_index = edata.get("edge_index", [[], []])
        if len(edge_index) > 0 and len(edge_index[0]) > 0:
            sources = edge_index[0]
            targets = edge_index[1]
            relation_name = f"{src_type}__{rel}__{dst_type}"
            
            for src, dst in zip(sources, targets):
                writer.writerow([relation_name, src_type, src, rel, dst_type, dst])
                total_edges_exported += 1

print("\n" + "=" * 70)
print(f"EXPORT COMPLETE: {total_edges_exported:,} TOTAL EDGES EXPORTED TO {output_csv}")
print("=" * 70)

# Print breakdown
print("\nEdge Count Breakdown by Relation:")
for (src_type, rel, dst_type), edata in edges_dict.items():
    edge_index = edata.get("edge_index", [[], []])
    num = len(edge_index[0]) if len(edge_index) > 0 else 0
    print(f"  - ({src_type} --[{rel}]--> {dst_type}): {num:,} edges")

print("\nYou can now open or inspect 'data/processed/full_graph_edges.csv' using Excel, pandas, or bash commands.")
