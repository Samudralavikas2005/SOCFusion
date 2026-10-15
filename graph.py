import csv
from collections import defaultdict

INPUT_FILE = "/tmp/day2_process_ids_all.txt"

NODE_FILE = "data/attack_nodes.csv"
EDGE_FILE = "data/attack_edges.csv"


# ============================================================
# STORAGE
# ============================================================

nodes = {}
edges = set()

# Flow statistics retained as PROCESS attributes
flow_counts = defaultdict(int)
flow_start_counts = defaultdict(int)
flow_message_counts = defaultdict(int)


# ============================================================
# HELPERS
# ============================================================

def add_node(node_id, node_type, label=None):
    if node_id not in nodes:
        nodes[node_id] = {
            "node_type": node_type,
            "label": label if label else node_id
        }


def add_edge(source, target, edge_type, timestamp):
    edges.add((source, target, edge_type, timestamp))


def process_node(pid):
    return f"process:{pid}"


def thread_node(tid):
    return f"thread:{tid}"


def module_node(mid):
    return f"module:{mid}"


def file_node(fid):
    return f"file:{fid}"


def command_node(cid):
    return f"command:{cid}"


def registry_node(rid):
    return f"registry:{rid}"


def task_node(tid):
    return f"task:{tid}"


# ============================================================
# PARSE DATA
# ============================================================

with open(INPUT_FILE, "r", errors="ignore") as f:

    for line in f:

        line = line.strip()

        # Ignore section headers
        if not line or line.startswith("PROCESS SECTION"):
            continue

        parts = line.split()

        # Expected structure:
        #
        # DATE TIME ACTION TYPE PID PPID UUID UUID LABEL
        #
        # Example:
        #
        # 2019-09-24 13:47:00.273000-04:00
        # CREATE PROCESS 2580 348 UUID UUID 1

        if len(parts) < 9:
            continue

        if parts[-1] != "1":
            continue

        timestamp = parts[0] + " " + parts[1]
        action = parts[2]
        event_type = parts[3]

        pid = parts[4]
        ppid = parts[5]

        uuid1 = parts[6]
        uuid2 = parts[7]


        # ====================================================
        # FLOW EVENTS
        # ====================================================

        if event_type == "FLOW":

            p = process_node(pid)

            add_node(
                p,
                "PROCESS",
                f"PID_{pid}"
            )

            flow_counts[p] += 1

            if action == "START":
                flow_start_counts[p] += 1

            elif action == "MESSAGE":
                flow_message_counts[p] += 1

            # IMPORTANT:
            #
            # We intentionally DO NOT create FLOW nodes.
            #
            # Flow activity is retained as process-level
            # information instead.
            #
            continue


        # ====================================================
        # PROCESS
        # ====================================================

        if event_type == "PROCESS":

            p = process_node(pid)

            add_node(
                p,
                "PROCESS",
                f"PID_{pid}"
            )

            # CREATE PROCESS
            if action == "CREATE":

                parent = process_node(ppid)

                add_node(
                    parent,
                    "PROCESS",
                    f"PID_{ppid}"
                )

                add_edge(
                    parent,
                    p,
                    "PROCESS_CREATE",
                    timestamp
                )

            # OPEN PROCESS
            elif action == "OPEN":

                target = process_node(pid)

                add_node(
                    target,
                    "PROCESS",
                    f"PID_{pid}"
                )

                # OPEN events are retained, but do not create
                # meaningless event nodes.
                add_edge(
                    process_node(ppid),
                    target,
                    "OPEN",
                    timestamp
                )

            continue


        # ====================================================
        # THREAD
        # ====================================================

        if event_type == "THREAD":

            t = thread_node(uuid2)

            add_node(
                t,
                "THREAD",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            # THREAD CREATE
            if action == "CREATE":

                add_edge(
                    owner,
                    t,
                    "THREAD_CREATE",
                    timestamp
                )

            # REMOTE THREAD
            elif action == "REMOTE_CREATE":

                add_edge(
                    owner,
                    t,
                    "REMOTE_THREAD",
                    timestamp
                )

            # THREAD TERMINATE
            elif action == "TERMINATE":

                add_edge(
                    t,
                    owner,
                    "THREAD_TERMINATE",
                    timestamp
                )

            continue


        # ====================================================
        # MODULE
        # ====================================================

        if event_type == "MODULE":

            m = module_node(uuid2)

            add_node(
                m,
                "MODULE",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            if action == "LOAD":

                add_edge(
                    owner,
                    m,
                    "MODULE_LOAD",
                    timestamp
                )

            continue


        # ====================================================
        # FILE
        # ====================================================

        if event_type == "FILE":

            fl = file_node(uuid2)

            add_node(
                fl,
                "FILE",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            edge_type = None

            if action == "CREATE":
                edge_type = "FILE_CREATE"

            elif action == "WRITE":
                edge_type = "FILE_WRITE"

            elif action == "READ":
                edge_type = "FILE_READ"

            elif action == "MODIFY":
                edge_type = "FILE_MODIFY"

            elif action == "RENAME":
                edge_type = "FILE_RENAME"

            if edge_type:

                add_edge(
                    owner,
                    fl,
                    edge_type,
                    timestamp
                )

            continue


        # ====================================================
        # SHELL COMMAND
        # ====================================================

        if event_type == "SHELL_COMMAND":

            cmd = command_node(uuid2)

            add_node(
                cmd,
                "SHELL_COMMAND",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            add_edge(
                owner,
                cmd,
                "SHELL_COMMAND",
                timestamp
            )

            continue


        # ====================================================
        # REGISTRY
        # ====================================================

        if event_type == "REGISTRY":

            reg = registry_node(uuid2)

            add_node(
                reg,
                "REGISTRY",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            if action == "EDIT":

                add_edge(
                    owner,
                    reg,
                    "REGISTRY_EDIT",
                    timestamp
                )

            continue


        # ====================================================
        # TASK
        # ====================================================

        if event_type == "TASK":

            task = task_node(uuid2)

            add_node(
                task,
                "TASK",
                uuid2
            )

            owner = process_node(pid)

            add_node(
                owner,
                "PROCESS",
                f"PID_{pid}"
            )

            if action == "START":

                add_edge(
                    owner,
                    task,
                    "START",
                    timestamp
                )

            continue


# ============================================================
# ADD FLOW FEATURES TO PROCESS NODES
# ============================================================

for node_id in nodes:

    if nodes[node_id]["node_type"] == "PROCESS":

        nodes[node_id]["flow_count"] = flow_counts[node_id]

        nodes[node_id]["flow_start_count"] = flow_start_counts[node_id]

        nodes[node_id]["flow_message_count"] = flow_message_counts[node_id]

    else:

        nodes[node_id]["flow_count"] = 0

        nodes[node_id]["flow_start_count"] = 0

        nodes[node_id]["flow_message_count"] = 0


# ============================================================
# WRITE NODE CSV
# ============================================================

with open(
    NODE_FILE,
    "w",
    newline=""
) as f:

    writer = csv.writer(f)

    writer.writerow([
        "node_id",
        "node_type",
        "label",
        "flow_count",
        "flow_start_count",
        "flow_message_count"
    ])

    for node_id, data in nodes.items():

        writer.writerow([
            node_id,
            data["node_type"],
            data["label"],
            data["flow_count"],
            data["flow_start_count"],
            data["flow_message_count"]
        ])


# ============================================================
# WRITE EDGE CSV
# ============================================================

with open(
    EDGE_FILE,
    "w",
    newline=""
) as f:

    writer = csv.writer(f)

    writer.writerow([
        "source",
        "target",
        "edge_type",
        "timestamp"
    ])

    for edge in sorted(edges, key=lambda x: x[3]):

        writer.writerow(edge)


# ============================================================
# SUMMARY
# ============================================================

print()
print("========== CLEAN GRAPH DATASET CREATED ==========")

print(f"Nodes : {len(nodes)}")
print(f"Edges : {len(edges)}")

print(f"Node file: {NODE_FILE}")
print(f"Edge file: {EDGE_FILE}")

print()
print("Flow events retained as PROCESS features.")
print("FLOW nodes removed from graph.")
print("Duplicate edges removed.")
print()
