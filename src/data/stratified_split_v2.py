import os
import pickle
import json
import numpy as np
from collections import defaultdict

BASE = "data/processed/graphs_v1"
OUT = "data/processed/graphs_final"

os.makedirs(OUT, exist_ok=True)

# ============================================================
# LOAD ORIGINAL GRAPHS
# ============================================================

datasets = {}

for name in ["train", "val", "test"]:
    print(f"Loading {name}...")
    with open(f"{BASE}/{name}_data.pt", "rb") as f:
        datasets[name] = pickle.load(f)

# ============================================================
# COMBINE EVENTS
# ============================================================

events = []
labels = []

for source_split in ["train", "val", "test"]:
    d = datasets[source_split]

    x = np.asarray(d["nodes"]["Event"]["x"], dtype=np.float32)
    y = np.asarray(d["nodes"]["Event"]["y"], dtype=np.int64)

    for i in range(len(y)):
        events.append((source_split, i))
        labels.append(int(y[i]))

labels = np.asarray(labels)

print()
print("========== COMBINED DATA ==========")
print("Events:", len(events))
print("Features:", datasets["train"]["nodes"]["Event"]["x"][0].__len__())

# ============================================================
# STRATIFIED SPLIT
# ============================================================

rng = np.random.default_rng(42)

by_class = defaultdict(list)

for i, label in enumerate(labels):
    by_class[label].append(i)

split_indices = {
    "train": [],
    "val": [],
    "test": []
}

for label, idxs in sorted(by_class.items()):
    idxs = np.asarray(idxs)
    rng.shuffle(idxs)

    n = len(idxs)

    n_train = int(n * 0.70)
    n_val = int(n * 0.15)

    # Keep at least one sample where possible
    if n >= 3:
        n_train = max(1, n_train)
        n_val = max(1, n_val)

    split_indices["train"].extend(idxs[:n_train])
    split_indices["val"].extend(idxs[n_train:n_train+n_val])
    split_indices["test"].extend(idxs[n_train+n_val:])

# ============================================================
# BUILD FAST LOOKUP
# ============================================================

# For every original graph:
# old_event_index -> global combined event index

global_lookup = {}

offset = 0

for source_split in ["train", "val", "test"]:
    n = len(datasets[source_split]["nodes"]["Event"]["y"])

    for local_idx in range(n):
        global_lookup[(source_split, local_idx)] = offset + local_idx

    offset += n

# ============================================================
# BUILD GRAPH
# ============================================================

def build_graph(selected):

    selected = list(selected)

    selected_set = set(selected)

    # Global combined index -> new local index
    global_to_local = {
        g: i for i, g in enumerate(selected)
    }

    # --------------------------------------------------------
    # EVENTS
    # --------------------------------------------------------

    X = []
    Y = []

    for g in selected:
        source, old_idx = events[g]

        d = datasets[source]

        X.append(d["nodes"]["Event"]["x"][old_idx])
        Y.append(d["nodes"]["Event"]["y"][old_idx])

    # --------------------------------------------------------
    # ENTITY MAPPINGS
    # --------------------------------------------------------

    host_map = {}
    user_map = {}
    process_map = {}

    run_edges = [[], []]
    exec_edges = [[], []]
    inv_edges = [[], []]
    spawn_edges = [[], []]
    precedes_edges = [[], []]

    # --------------------------------------------------------
    # EVENT -> ENTITY EDGES
    # --------------------------------------------------------

    for source_split in ["train", "val", "test"]:

        d = datasets[source_split]

        # Events belonging to this original graph that survived
        local_event_map = {}

        for old_idx in range(
            d["nodes"]["Event"]["num_nodes"]
        ):
            g = global_lookup[(source_split, old_idx)]

            if g in global_to_local:
                local_event_map[old_idx] = global_to_local[g]

        if not local_event_map:
            continue

        # EVENT -> HOST
        edge = d["edges"].get(
            ("Event", "RUNS_ON", "Host")
        )

        if edge:
            srcs, dsts = edge["edge_index"]

            for src, dst in zip(srcs, dsts):

                src = int(src)
                dst = int(dst)

                if src not in local_event_map:
                    continue

                key = (source_split, dst)

                if key not in host_map:
                    host_map[key] = len(host_map)

                run_edges[0].append(local_event_map[src])
                run_edges[1].append(host_map[key])

        # EVENT -> USER
        edge = d["edges"].get(
            ("Event", "EXECUTED_BY", "User")
        )

        if edge:
            srcs, dsts = edge["edge_index"]

            for src, dst in zip(srcs, dsts):

                src = int(src)
                dst = int(dst)

                if src not in local_event_map:
                    continue

                key = (source_split, dst)

                if key not in user_map:
                    user_map[key] = len(user_map)

                exec_edges[0].append(local_event_map[src])
                exec_edges[1].append(user_map[key])

        # EVENT -> PROCESS
        edge = d["edges"].get(
            ("Event", "INVOLVES", "Process")
        )

        if edge:
            srcs, dsts = edge["edge_index"]

            for src, dst in zip(srcs, dsts):

                src = int(src)
                dst = int(dst)

                if src not in local_event_map:
                    continue

                key = (source_split, dst)

                if key not in process_map:
                    process_map[key] = len(process_map)

                inv_edges[0].append(local_event_map[src])
                inv_edges[1].append(process_map[key])

        # EVENT -> EVENT PRECEDES
        edge = d["edges"].get(
            ("Event", "PRECEDES", "Event")
        )

        if edge:
            srcs, dsts = edge["edge_index"]

            for src, dst in zip(srcs, dsts):

                src = int(src)
                dst = int(dst)

                if (
                    src in local_event_map
                    and dst in local_event_map
                ):
                    precedes_edges[0].append(
                        local_event_map[src]
                    )
                    precedes_edges[1].append(
                        local_event_map[dst]
                    )

    # --------------------------------------------------------
    # PROCESS -> PROCESS SPAWNED
    # --------------------------------------------------------

    selected_processes = set(process_map.keys())

    for source_split in ["train", "val", "test"]:

        d = datasets[source_split]

        edge = d["edges"].get(
            ("Process", "SPAWNED", "Process")
        )

        if not edge:
            continue

        srcs, dsts = edge["edge_index"]

        for src, dst in zip(srcs, dsts):

            src = int(src)
            dst = int(dst)

            src_key = (source_split, src)
            dst_key = (source_split, dst)

            if (
                src_key in selected_processes
                and dst_key in selected_processes
            ):
                spawn_edges[0].append(
                    process_map[src_key]
                )
                spawn_edges[1].append(
                    process_map[dst_key]
                )

    # --------------------------------------------------------
    # GRAPH
    # --------------------------------------------------------

    return {
        "nodes": {
            "Event": {
                "x": np.asarray(X, dtype=np.float32).tolist(),
                "y": np.asarray(Y, dtype=np.int64).tolist(),
                "num_nodes": len(X)
            },
            "Host": {
                "num_nodes": len(host_map)
            },
            "User": {
                "num_nodes": len(user_map)
            },
            "Process": {
                "num_nodes": len(process_map)
            }
        },
        "edges": {
            ("Event", "RUNS_ON", "Host"):
                {"edge_index": run_edges},

            ("Event", "EXECUTED_BY", "User"):
                {"edge_index": exec_edges},

            ("Event", "INVOLVES", "Process"):
                {"edge_index": inv_edges},

            ("Process", "SPAWNED", "Process"):
                {"edge_index": spawn_edges},

            ("Event", "PRECEDES", "Event"):
                {"edge_index": precedes_edges}
        }
    }

# ============================================================
# WRITE
# ============================================================

for name in ["train", "val", "test"]:

    print()
    print("=" * 60)
    print(f"BUILDING {name.upper()}")
    print("=" * 60)

    graph = build_graph(split_indices[name])

    with open(
        f"{OUT}/{name}_data.pt",
        "wb"
    ) as f:
        pickle.dump(graph, f)

    print("Events   :", graph["nodes"]["Event"]["num_nodes"])
    print("Hosts    :", graph["nodes"]["Host"]["num_nodes"])
    print("Users    :", graph["nodes"]["User"]["num_nodes"])
    print("Processes:", graph["nodes"]["Process"]["num_nodes"])

    for edge_type, edge_data in graph["edges"].items():
        print(
            edge_type,
            ":",
            len(edge_data["edge_index"][0]),
            "edges"
        )

# LABEL MAP
with open(f"{BASE}/label_mapping.json") as f:
    label_map = json.load(f)

with open(f"{OUT}/label_mapping.json", "w") as f:
    json.dump(label_map, f, indent=2)

print()
print("========== COMPLETE ==========")
print("Output:", OUT)
