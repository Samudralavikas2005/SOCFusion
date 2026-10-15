import csv
from collections import defaultdict
from datetime import datetime

NODE_FILE = "data/attack_nodes.csv"
EDGE_FILE = "data/attack_edges.csv"
OUTPUT_FILE = "data/attack_chains.txt"


# ============================================================
# LOAD NODES
# ============================================================

nodes = {}

with open(NODE_FILE, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        nodes[row["node_id"]] = row


# ============================================================
# LOAD EDGES
# ============================================================

edges = []

with open(EDGE_FILE, newline="") as f:
    reader = csv.DictReader(f)

    for row in reader:
        edges.append({
            "source": row["source"],
            "target": row["target"],
            "type": row["edge_type"],
            "timestamp": row["timestamp"]
        })


# ============================================================
# HELPERS
# ============================================================

def parse_time(value):
    try:
        dt = datetime.fromisoformat(value)

        # Convert timezone-aware timestamps to a naive UTC-like
        # representation so all timestamps can be compared safely.
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)

        return dt

    except Exception:
        return datetime.min

def is_process(node_id):
    return node_id.startswith("process:")


def is_thread(node_id):
    return node_id.startswith("thread:")


# ============================================================
# BUILD PROCESS-CREATE RELATIONSHIPS
# ============================================================

process_create = []

for edge in edges:
    if (
        edge["type"] == "PROCESS_CREATE"
        and is_process(edge["source"])
        and is_process(edge["target"])
    ):
        process_create.append(edge)


process_create.sort(key=lambda x: parse_time(x["timestamp"]))


parent_of = {}
children_of = defaultdict(list)

for edge in process_create:
    parent = edge["source"]
    child = edge["target"]

    parent_of[child] = parent
    children_of[parent].append(child)


# ============================================================
# BUILD REMOTE THREAD RELATIONSHIPS
# ============================================================

remote_threads = []

for edge in edges:
    if edge["type"] == "REMOTE_THREAD":
        remote_threads.append(edge)

remote_threads.sort(key=lambda x: parse_time(x["timestamp"]))


# ============================================================
# ALL PROCESS NODES
# ============================================================

process_nodes = sorted(
    [node_id for node_id in nodes if is_process(node_id)]
)


# ============================================================
# ROOT PROCESSES
#
# A root process has no PROCESS_CREATE parent.
# ============================================================

roots = [
    p for p in process_nodes
    if p not in parent_of
]


# ============================================================
# BUILD PROCESS CHAINS
# ============================================================

chains = []

visited = set()


def build_chain(root):
    chain = [root]
    current = root

    while current in children_of:

        children = sorted(
            children_of[current],
            key=lambda x: next(
                (
                    parse_time(e["timestamp"])
                    for e in process_create
                    if e["source"] == current
                    and e["target"] == x
                ),
                datetime.min
            )
        )

        if not children:
            break

        # Follow the first chronological child.
        # Additional children are handled separately.
        child = children[0]

        if child in chain:
            break

        chain.append(child)
        current = child

    return chain


for root in roots:

    chain = build_chain(root)

    if len(chain) > 1:
        for node in chain:
            visited.add(node)

        chains.append(chain)


# ============================================================
# PRINT SUMMARY
# ============================================================

print()
print("========== ATTACK RECONSTRUCTION ENGINE ==========")
print()

print(f"Total nodes       : {len(nodes)}")
print(f"Total edges       : {len(edges)}")
print(f"Process nodes     : {len(process_nodes)}")
print(f"Process relations : {len(process_create)}")
print(f"Root processes    : {len(roots)}")
print(f"Chains discovered : {len(chains)}")


# ============================================================
# PROCESS-CREATE ATTACK LINEAGE
# ============================================================

print()
print("========== PROCESS CREATE LINEAGE ==========")
print()

if not process_create:
    print("No PROCESS_CREATE relationships found.")

else:

    for edge in process_create:
        print(
            f'{edge["timestamp"]} | '
            f'{edge["source"]} --[PROCESS_CREATE]--> '
            f'{edge["target"]}'
        )


# ============================================================
# REMOTE THREAD EVIDENCE
# ============================================================

print()
print("========== REMOTE THREAD EVIDENCE ==========")
print()

for edge in remote_threads:
    print(
        f'{edge["timestamp"]} | '
        f'{edge["source"]} --[REMOTE_THREAD]--> '
        f'{edge["target"]}'
    )


# ============================================================
# PRIMARY ATTACK CHAINS
# ============================================================

print()
print("========== RECONSTRUCTED ATTACK CHAINS ==========")
print()

if not chains:
    print("No multi-process attack chains discovered.")

else:

    for i, chain in enumerate(chains, start=1):

        print(f"CHAIN #{i}")

        for j, process in enumerate(chain):

            print(f"  {process}")

            if j < len(chain) - 1:

                child = chain[j + 1]

                relation = next(
                    (
                        e for e in process_create
                        if e["source"] == process
                        and e["target"] == child
                    ),
                    None
                )

                if relation:
                    print(
                        f"    |--[PROCESS_CREATE] "
                        f"{relation['timestamp']}"
                    )
                    print("    v")

        print()


# ============================================================
# EXPAND EACH ATTACK PROCESS WITH REMOTE THREADS
# ============================================================

print()
print("========== ATTACK PROCESS EVIDENCE ==========")
print()

attack_processes = set()

for chain in chains:
    attack_processes.update(chain)


for process in sorted(
    attack_processes,
    key=lambda x: (
        parse_time(
            next(
                (
                    e["timestamp"]
                    for e in process_create
                    if e["target"] == x
                ),
                "9999-12-31T00:00:00"
            )
        ),
        x
    )
):

    print(process)

    related_threads = [
        e for e in remote_threads
        if e["source"] == process
    ]

    for edge in related_threads:
        print(
            f"  |--[REMOTE_THREAD] {edge['timestamp']}"
        )
        print(
            f"  v {edge['target']}"
        )

    print()


# ============================================================
# SUPPORTING EVENTS FOR ATTACK PROCESSES
# ============================================================

print()
print("========== SUPPORTING ATTACK EVENTS ==========")
print()

supporting_types = {
    "OPEN",
    "FILE_CREATE",
    "FILE_WRITE",
    "FILE_READ",
    "FILE_MODIFY",
    "FILE_RENAME",
    "THREAD_CREATE",
    "THREAD_TERMINATE",
    "MODULE_LOAD",
    "SHELL_COMMAND",
    "REGISTRY_EDIT",
    "START",
}


attack_processes = set()

for chain in chains:
    attack_processes.update(chain)


supporting_events = []

for edge in edges:

    if (
        edge["source"] in attack_processes
        and edge["type"] in supporting_types
    ):
        supporting_events.append(edge)


supporting_events.sort(
    key=lambda x: parse_time(x["timestamp"])
)


for edge in supporting_events:

    print(
        f'{edge["timestamp"]} | '
        f'{edge["source"]} --[{edge["type"]}]--> '
        f'{edge["target"]}'
    )


# ============================================================
# SAVE OUTPUT
# ============================================================

with open(OUTPUT_FILE, "w") as f:

    f.write("========== SOCFUSION ATTACK RECONSTRUCTION ==========\n\n")

    f.write(f"Total nodes       : {len(nodes)}\n")
    f.write(f"Total edges       : {len(edges)}\n")
    f.write(f"Process nodes     : {len(process_nodes)}\n")
    f.write(f"Process relations : {len(process_create)}\n")
    f.write(f"Root processes    : {len(roots)}\n")
    f.write(f"Chains discovered : {len(chains)}\n\n")

    f.write("========== PRIMARY PROCESS ATTACK CHAINS ==========\n\n")

    for i, chain in enumerate(chains, start=1):

        f.write(f"CHAIN #{i}\n")

        for j, process in enumerate(chain):

            f.write(f"  {process}\n")

            if j < len(chain) - 1:

                child = chain[j + 1]

                relation = next(
                    (
                        e for e in process_create
                        if e["source"] == process
                        and e["target"] == child
                    ),
                    None
                )

                if relation:

                    f.write(
                        f"    |--[PROCESS_CREATE] "
                        f"{relation['timestamp']}\n"
                    )

                    f.write("    v\n")

        f.write("\n")

    f.write("========== PROCESS CREATE RELATIONSHIPS ==========\n\n")

    for edge in process_create:

        f.write(
            f'{edge["timestamp"]} | '
            f'{edge["source"]} --[PROCESS_CREATE]--> '
            f'{edge["target"]}\n'
        )

    f.write("\n========== REMOTE THREAD RELATIONSHIPS ==========\n\n")

    for edge in remote_threads:

        f.write(
            f'{edge["timestamp"]} | '
            f'{edge["source"]} --[REMOTE_THREAD]--> '
            f'{edge["target"]}\n'
        )

    f.write("\n========== SUPPORTING ATTACK EVENTS ==========\n\n")

    for edge in supporting_events:

        f.write(
            f'{edge["timestamp"]} | '
            f'{edge["source"]} --[{edge["type"]}]--> '
            f'{edge["target"]}\n'
        )


print()
print("========== RECONSTRUCTION COMPLETE ==========")
print()
print(f"Output: {OUTPUT_FILE}")
print()
