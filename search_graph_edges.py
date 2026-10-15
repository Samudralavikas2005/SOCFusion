import csv
import sys

csv_path = "data/processed/full_graph_edges.csv"

rel_filter = sys.argv[1] if len(sys.argv) > 1 else "PRECEDES"
limit = int(sys.argv[2]) if len(sys.argv) > 2 else 50

print("\n" + "=" * 70)
print(f"SEARCHING GRAPH EDGES (Filter: '{rel_filter}', Display Limit: {limit})")
print(f"CSV File: {csv_path}")
print("=" * 70)

matching_rows = []

with open(csv_path, "r", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for row in reader:
        if rel_filter.upper() in row["relation"].upper() or rel_filter.upper() in row["edge_type"].upper():
            matching_rows.append(row)

print(f"\nTotal Matching Edges Found: {len(matching_rows):,}")
print(f"Displaying First {min(limit, len(matching_rows))} Edges:\n")

print(f"{'#':<6} | {'Source Node':<15} | {'Relation':<12} | {'Target Node':<15}")
print("-" * 60)

for i, row in enumerate(matching_rows[:limit], start=1):
    src = f"{row['source_node_type']} {row['source_node_id']}"
    tgt = f"{row['target_node_type']} {row['target_node_id']}"
    rel = row['relation']
    print(f"{i:<6d} | {src:<15s} | {rel:<12s} | {tgt:<15s}")

if len(matching_rows) > limit:
    print(f"\n... and {len(matching_rows) - limit:,} more matching edges stored in data/processed/full_graph_edges.csv")

print("=" * 70)
