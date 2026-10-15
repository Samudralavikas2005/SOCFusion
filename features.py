import csv
import torch

from datetime import datetime

from torch_geometric.data import Data


# ============================================================
# FILES
# ============================================================

NODE_FILE = "data/attack_nodes.csv"
EDGE_FILE = "data/attack_edges.csv"
OUTPUT_FILE = "data/attack_graph.pt"


# ============================================================
# NODE TYPE ENCODING
# ============================================================

NODE_TYPE_MAP = {
    "PROCESS": 0,
    "THREAD": 1,
    "MODULE": 2,
    "FILE": 3,
    "SHELL_COMMAND": 4,
    "REGISTRY": 5,
    "TASK": 6,
}


# ============================================================
# EDGE TYPE ENCODING
# ============================================================

EDGE_TYPE_MAP = {
    "PROCESS_CREATE": 0,
    "REMOTE_THREAD": 1,
    "THREAD_CREATE": 2,
    "THREAD_TERMINATE": 3,
    "MODULE_LOAD": 4,
    "FILE_CREATE": 5,
    "FILE_WRITE": 6,
    "FILE_READ": 7,
    "FILE_MODIFY": 8,
    "FILE_RENAME": 9,
    "SHELL_COMMAND": 10,
    "REGISTRY_EDIT": 11,
    "START": 12,
    "OPEN": 13,
}


# ============================================================
# LOAD NODES
# ============================================================

nodes = {}
node_order = []

with open(NODE_FILE, newline="", errors="ignore") as f:

    reader = csv.DictReader(f)

    for row in reader:

        node_id = row["node_id"]

        node_order.append(node_id)

        nodes[node_id] = {
            "node_type": row["node_type"],
            "flow_count": float(row["flow_count"]),
            "flow_start_count": float(row["flow_start_count"]),
            "flow_message_count": float(row["flow_message_count"]),
        }


# ============================================================
# NODE ID → INTEGER INDEX
# ============================================================

node_to_idx = {
    node_id: i
    for i, node_id in enumerate(node_order)
}


# ============================================================
# LOAD EDGES
# ============================================================

edges = []

timestamps = []

with open(EDGE_FILE, newline="", errors="ignore") as f:

    reader = csv.DictReader(f)

    for row in reader:

        source = row["source"]
        target = row["target"]
        edge_type = row["edge_type"]
        timestamp = row["timestamp"]

        if source not in node_to_idx:
            continue

        if target not in node_to_idx:
            continue

        edges.append(
            (
                node_to_idx[source],
                node_to_idx[target],
                edge_type,
                timestamp,
            )
        )

        timestamps.append(timestamp)


# ============================================================
# DEGREE FEATURES
# ============================================================

in_degree = [0] * len(node_order)
out_degree = [0] * len(node_order)

for source, target, _, _ in edges:

    out_degree[source] += 1
    in_degree[target] += 1


# ============================================================
# BUILD NODE FEATURES
# ============================================================

node_features = []

for idx, node_id in enumerate(node_order):

    info = nodes[node_id]

    node_type = info["node_type"]

    if node_type not in NODE_TYPE_MAP:
        raise ValueError(
            f"Unknown node type: {node_type}"
        )

    node_type_id = NODE_TYPE_MAP[node_type]

    # --------------------------------------------------------
    # One-hot node type
    # --------------------------------------------------------

    type_vector = [
        0.0
        for _ in range(len(NODE_TYPE_MAP))
    ]

    type_vector[node_type_id] = 1.0

    # --------------------------------------------------------
    # Numerical features
    # --------------------------------------------------------

    feature_vector = type_vector + [

        # Flow activity
        info["flow_count"],
        info["flow_start_count"],
        info["flow_message_count"],

        # Graph structure
        float(in_degree[idx]),
        float(out_degree[idx]),
    ]

    node_features.append(feature_vector)


x = torch.tensor(
    node_features,
    dtype=torch.float
)


# ============================================================
# NORMALIZE NUMERICAL FEATURES
# ============================================================

# Features after the one-hot node type columns
#
# [flow_count,
#  flow_start_count,
#  flow_message_count,
#  in_degree,
#  out_degree]

numeric_start = len(NODE_TYPE_MAP)

numeric = x[:, numeric_start:]

mean = numeric.mean(dim=0)

std = numeric.std(
    dim=0,
    unbiased=False
)

# Avoid division by zero
std[std == 0] = 1.0

x[:, numeric_start:] = (
    numeric - mean
) / std


# ============================================================
# BUILD EDGE INDEX
# ============================================================

edge_index = []

edge_type_ids = []

edge_time_values = []


# ============================================================
# TIMESTAMP BASE
# ============================================================

if timestamps:

    parsed_times = [
        datetime.fromisoformat(
            t
        )
        for t in timestamps
    ]

    base_time = min(parsed_times)

else:

    base_time = None


# ============================================================
# BUILD EDGES
# ============================================================

for source, target, edge_type, timestamp in edges:

    edge_index.append(
        [
            source,
            target
        ]
    )

    if edge_type not in EDGE_TYPE_MAP:

        raise ValueError(
            f"Unknown edge type: {edge_type}"
        )

    edge_type_ids.append(
        EDGE_TYPE_MAP[edge_type]
    )

    if base_time is not None:

        current_time = datetime.fromisoformat(
            timestamp
        )

        delta = (
            current_time - base_time
        ).total_seconds()

        edge_time_values.append(delta)

    else:

        edge_time_values.append(0.0)


# ============================================================
# TENSORS
# ============================================================

if edge_index:

    edge_index_tensor = torch.tensor(
        edge_index,
        dtype=torch.long
    ).t().contiguous()

else:

    edge_index_tensor = torch.empty(
        (2, 0),
        dtype=torch.long
    )


edge_type_tensor = torch.tensor(
    edge_type_ids,
    dtype=torch.long
)


edge_time_tensor = torch.tensor(
    edge_time_values,
    dtype=torch.float
)


# ============================================================
# NORMALIZE EDGE TIME
# ============================================================

if edge_time_tensor.numel() > 0:

    time_std = edge_time_tensor.std(
        unbiased=False
    )

    if time_std == 0:
        time_std = 1.0

    edge_time_tensor = (
        edge_time_tensor
        - edge_time_tensor.mean()
    ) / time_std


# ============================================================
# CREATE PYTORCH GEOMETRIC GRAPH
# ============================================================

data = Data(
    x=x,
    edge_index=edge_index_tensor,
)


# Store additional information
data.edge_type = edge_type_tensor
data.edge_time = edge_time_tensor


# Useful metadata
data.num_node_types = len(
    NODE_TYPE_MAP
)

data.num_edge_types = len(
    EDGE_TYPE_MAP
)


# ============================================================
# SAVE
# ============================================================

torch.save(
    data,
    OUTPUT_FILE
)


# ============================================================
# SUMMARY
# ============================================================

print()
print("========== PYTORCH GEOMETRIC GRAPH CREATED ==========")

print(
    f"Nodes              : {data.num_nodes}"
)

print(
    f"Edges              : {data.num_edges}"
)

print(
    f"Node feature size  : {data.num_node_features}"
)

print(
    f"Node feature shape : {tuple(data.x.shape)}"
)

print(
    f"Edge index shape   : {tuple(data.edge_index.shape)}"
)

print(
    f"Edge type shape    : {tuple(data.edge_type.shape)}"
)

print(
    f"Edge time shape    : {tuple(data.edge_time.shape)}"
)

print()
print("Node types:")

for name, idx in NODE_TYPE_MAP.items():
    print(f"  {idx}: {name}")

print()
print("Edge types:")

for name, idx in EDGE_TYPE_MAP.items():
    print(f"  {idx}: {name}")

print()
print(f"Saved to: {OUTPUT_FILE}")
