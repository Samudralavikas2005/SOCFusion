import os
import json
import csv
import pickle
from collections import defaultdict, Counter
from src.attack_chain.simplifier import simplify_technique_chain


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

GRAPH_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/graphs_final_norm/test_data.pt"
)

PREDICTIONS_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/gat_v2_predictions/test_predictions.csv"
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "data/processed/attack_chains_v4"
)


# ============================================================
# PARAMETERS
# ============================================================

# Minimum number of events required for a chain.
MIN_CHAIN_LENGTH = 2

# Maximum number of events allowed in one reconstructed chain.
# This prevents accidental giant components.
MAX_CHAIN_LENGTH = 50

# A PRECEDES edge must directly connect two events.
# We do NOT connect events merely because they have the same host.
#
# Process relationships are stronger evidence than host relationships.
#
# Event pairs can be connected when:
#   1. Event -> Process
#   2. Event -> Process and the process relationships match
#   3. Event -> PRECEDES -> Event
#
# Prediction similarity is used as a validation signal.


# ============================================================
# LOAD GRAPH
# ============================================================

def load_graph(path):

    print(f"Loading graph: {path}")

    with open(path, "rb") as f:
        raw = pickle.load(f)

    print("Graph loaded successfully.")

    return raw


# ============================================================
# LOAD PREDICTIONS
# ============================================================

def load_predictions(path):

    print(f"Loading predictions: {path}")

    predictions = {}

    with open(path, newline="") as f:

        reader = csv.DictReader(f)

        for row in reader:

            event_index = int(row["event_index"])

            predictions[event_index] = {
                "predicted_class": int(row["predicted_class"]),
                "predicted_technique": row["predicted_technique"],
                "confidence": float(row["confidence"])
            }

    print(
        f"Loaded predictions for "
        f"{len(predictions)} events."
    )

    return predictions


# ============================================================
# GRAPH HELPERS
# ============================================================

def edge_set(raw, edge_type):

    if edge_type not in raw["edges"]:
        return set()

    edge_index = raw["edges"][edge_type]["edge_index"]

    return set(
        zip(
            edge_index[0],
            edge_index[1]
        )
    )


def build_event_relationships(raw):

    nodes = raw["nodes"]
    edges = raw["edges"]

    num_events = nodes["Event"]["num_nodes"]

    # --------------------------------------------------------
    # Event -> Host
    # --------------------------------------------------------

    event_host = {}

    key = ("Event", "RUNS_ON", "Host")

    if key in edges:

        edge_index = edges[key]["edge_index"]

        for e, h in zip(
            edge_index[0],
            edge_index[1]
        ):
            event_host[int(e)] = int(h)

    # --------------------------------------------------------
    # Event -> User
    # --------------------------------------------------------

    event_user = {}

    key = ("Event", "EXECUTED_BY", "User")

    if key in edges:

        edge_index = edges[key]["edge_index"]

        for e, u in zip(
            edge_index[0],
            edge_index[1]
        ):
            event_user[int(e)] = int(u)

    # --------------------------------------------------------
    # Event -> Process
    # --------------------------------------------------------

    event_processes = defaultdict(set)

    key = ("Event", "INVOLVES", "Process")

    if key in edges:

        edge_index = edges[key]["edge_index"]

        for e, p in zip(
            edge_index[0],
            edge_index[1]
        ):
            event_processes[int(e)].add(int(p))

    # --------------------------------------------------------
    # Process -> Process
    # --------------------------------------------------------

    process_children = defaultdict(set)

    key = ("Process", "SPAWNED", "Process")

    if key in edges:

        edge_index = edges[key]["edge_index"]

        for parent, child in zip(
            edge_index[0],
            edge_index[1]
        ):
            process_children[int(parent)].add(
                int(child)
            )

    # --------------------------------------------------------
    # PRECEDES
    # --------------------------------------------------------

    precedes = []

    key = ("Event", "PRECEDES", "Event")

    if key in edges:

        edge_index = edges[key]["edge_index"]

        for src, dst in zip(
            edge_index[0],
            edge_index[1]
        ):

            precedes.append(
                (int(src), int(dst))
            )

    return (
        num_events,
        event_host,
        event_user,
        event_processes,
        process_children,
        precedes
    )


# ============================================================
# PROCESS CONNECTIVITY
# ============================================================

def build_process_connected_events(
    event_processes,
    process_children
):

    process_to_events = defaultdict(set)

    # Event -> Process

    for event, processes in event_processes.items():

        for process in processes:

            process_to_events[process].add(event)

    # --------------------------------------------------------
    # Build process graph
    # --------------------------------------------------------

    process_graph = defaultdict(set)

    for parent, children in process_children.items():

        for child in children:

            process_graph[parent].add(child)
            process_graph[child].add(parent)

    # --------------------------------------------------------
    # Find process components
    # --------------------------------------------------------

    visited = set()

    process_component = {}

    component_id = 0

    all_processes = set(process_to_events)

    for parent, children in process_children.items():

        all_processes.add(parent)

        all_processes.update(children)

    for process in all_processes:

        if process in visited:
            continue

        stack = [process]

        visited.add(process)

        component_processes = []

        while stack:

            current = stack.pop()

            component_processes.append(current)

            for neighbour in process_graph[current]:

                if neighbour not in visited:

                    visited.add(neighbour)

                    stack.append(neighbour)

        for p in component_processes:

            process_component[p] = component_id

        component_id += 1

    # --------------------------------------------------------
    # Map process components -> events
    # --------------------------------------------------------

    component_events = defaultdict(set)

    for process, events in process_to_events.items():

        component = process_component.get(
            process
        )

        if component is None:
            continue

        for event in events:

            component_events[component].add(
                event
            )

    return component_events


# ============================================================
# UNION FIND
# ============================================================

class UnionFind:

    def __init__(self, n):

        self.parent = list(range(n))
        self.size = [1] * n

    def find(self, x):

        while self.parent[x] != x:

            self.parent[x] = (
                self.parent[self.parent[x]]
            )

            x = self.parent[x]

        return x

    def union(self, a, b):

        ra = self.find(a)
        rb = self.find(b)

        if ra == rb:
            return False

        # Keep smaller root under larger root.

        if self.size[ra] < self.size[rb]:

            ra, rb = rb, ra

        self.parent[rb] = ra

        self.size[ra] += self.size[rb]

        return True


# ============================================================
# BUILD CHAINS
# ============================================================

def reconstruct_chains(
    num_events,
    event_host,
    event_user,
    event_processes,
    process_children,
    precedes,
    predictions
):

    print()
    print("=" * 70)
    print("BUILDING GRAPH-CONSTRAINED CHAINS")
    print("=" * 70)

    uf = UnionFind(num_events)

    connection_reason = defaultdict(list)

    # --------------------------------------------------------
    # 1. PROCESS COMPONENT CONNECTIONS
    # --------------------------------------------------------

    component_events = build_process_connected_events(
        event_processes,
        process_children
    )

    process_connections = 0

    for events in component_events.values():

        events = sorted(events)

        if len(events) < 2:
            continue

        # IMPORTANT:
        # Do not blindly connect every event in a giant
        # process component.
        #
        # Connect only consecutive events.

        for a, b in zip(
            events,
            events[1:]
        ):

            if (
                event_host.get(a)
                != event_host.get(b)
            ):
                continue

            uf.union(a, b)

            connection_reason[
                tuple(sorted((a, b)))
            ].append("PROCESS")

            process_connections += 1

    # --------------------------------------------------------
    # 2. DIRECT PRECEDES CONNECTIONS
    # --------------------------------------------------------

    precedes_connections = 0

    for a, b in precedes:

        if a == b:
            continue

        # Require same host when host information exists.

        host_a = event_host.get(a)
        host_b = event_host.get(b)

        if (
            host_a is not None
            and host_b is not None
            and host_a != host_b
        ):
            continue

        # Require prediction information.

        if (
            a not in predictions
            or b not in predictions
        ):
            continue

        uf.union(a, b)

        connection_reason[
            tuple(sorted((a, b)))
        ].append("PRECEDES")

        precedes_connections += 1

    print(
        f"Process connections: "
        f"{process_connections}"
    )

    print(
        f"PRECEDES connections: "
        f"{precedes_connections}"
    )

    # --------------------------------------------------------
    # 3. CREATE COMPONENTS
    # --------------------------------------------------------

    components = defaultdict(list)

    for event in range(num_events):

        root = uf.find(event)

        components[root].append(event)

    # --------------------------------------------------------
    # 4. FILTER GIANT / SINGLE COMPONENTS
    # --------------------------------------------------------

    candidate_chains = []

    rejected_small = 0
    rejected_large = 0

    for events in components.values():

        events = sorted(events)

        if len(events) < MIN_CHAIN_LENGTH:

            rejected_small += 1
            continue

        if len(events) > MAX_CHAIN_LENGTH:

            rejected_large += 1
            continue

        candidate_chains.append(events)

    print()
    print(
        f"Raw components: "
        f"{len(components)}"
    )

    print(
        f"Rejected small components: "
        f"{rejected_small}"
    )

    print(
        f"Rejected giant components: "
        f"{rejected_large}"
    )

    print(
        f"Candidate chains: "
        f"{len(candidate_chains)}"
    )

    return candidate_chains


# ============================================================
# VALIDATE CHAINS
# ============================================================

def validate_chains(
    chains,
    event_host,
    event_user,
    event_processes,
    predictions
):

    validated = []

    for index, events in enumerate(
        chains,
        start=1
    ):

        # ----------------------------------------------------
        # Techniques
        # ----------------------------------------------------

        techniques = []

        confidences = []

        for event in events:

            pred = predictions.get(event)

            if pred is None:
                continue

            techniques.append(
                pred["predicted_technique"]
            )

            confidences.append(
                pred["confidence"]
            )

        if not techniques:
            continue

        # ----------------------------------------------------
        # Collapse consecutive duplicate techniques.
        # ----------------------------------------------------

        collapsed = []

        for technique in techniques:

            if (
                not collapsed
                or collapsed[-1] != technique
            ):
                collapsed.append(technique)

        # ----------------------------------------------------
        # First-seen chronological simplified technique narrative.
        # ----------------------------------------------------

        simplified = simplify_technique_chain(techniques)

        # ----------------------------------------------------
        # Require at least two distinct techniques OR
        # a meaningful process/precedence chain.
        #
        # We retain single-technique chains because they are
        # still useful for dashboard investigation.
        # ----------------------------------------------------

        unique_techniques = sorted(
            set(techniques)
        )

        hosts = sorted(
            set(
                event_host[e]
                for e in events
                if e in event_host
            )
        )

        users = sorted(
            set(
                event_user[e]
                for e in events
                if e in event_user
            )
        )

        processes = sorted(
            set(
                p
                for e in events
                for p in event_processes.get(
                    e,
                    set()
                )
            )
        )

        avg_confidence = (
            sum(confidences)
            / len(confidences)
            if confidences
            else 0.0
        )

        chain_id = (
            f"GATV2_CHAIN_{index:06d}"
        )

        validated.append(
            {
                "chain_id": chain_id,
                "num_events": len(events),
                "events": events,
                "techniques": techniques,
                "collapsed_techniques": collapsed,
                "simplified_techniques": simplified,
                "unique_techniques": unique_techniques,
                "num_unique_techniques": len(
                    unique_techniques
                ),
                "num_simplified_techniques": len(
                    simplified
                ),
                "average_confidence": avg_confidence,
                "hosts": hosts,
                "users": users,
                "processes": processes
            }
        )

    return validated


# ============================================================
# SAVE RESULTS
# ============================================================

def save_results(
    chains,
    predictions,
    event_host,
    event_user,
    event_processes
):

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    json_path = os.path.join(
        OUTPUT_DIR,
        "reconstructed_attack_chains.json"
    )

    csv_path = os.path.join(
        OUTPUT_DIR,
        "chain_events.csv"
    )

    stats_path = os.path.join(
        OUTPUT_DIR,
        "chain_statistics.json"
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    with open(
        json_path,
        "w"
    ) as f:

        json.dump(
            chains,
            f,
            indent=2
        )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    with open(
        csv_path,
        "w",
        newline=""
    ) as f:

        writer = csv.writer(f)

        writer.writerow(
            [
                "chain_id",
                "event_index",
                "predicted_class",
                "predicted_technique",
                "confidence",
                "host",
                "user",
                "processes"
            ]
        )

        for chain in chains:

            for event in chain["events"]:

                pred = predictions[event]

                writer.writerow(
                    [
                        chain["chain_id"],
                        event,
                        pred["predicted_class"],
                        pred["predicted_technique"],
                        pred["confidence"],
                        event_host.get(
                            event,
                            -1
                        ),
                        event_user.get(
                            event,
                            -1
                        ),
                        ",".join(
                            map(
                                str,
                                sorted(
                                    event_processes.get(
                                        event,
                                        set()
                                    )
                                )
                            )
                        )
                    ]
                )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    lengths = [
        c["num_events"]
        for c in chains
    ]

    technique_counter = Counter()

    for chain in chains:

        for technique in chain["techniques"]:

            technique_counter[
                technique
            ] += 1

    total_events = sum(lengths)

    stats = {

        "total_chains": len(chains),

        "total_events": total_events,

        "minimum_chain_length": (
            min(lengths)
            if lengths
            else 0
        ),

        "maximum_chain_length": (
            max(lengths)
            if lengths
            else 0
        ),

        "average_chain_length": (
            total_events / len(chains)
            if chains
            else 0
        ),

        "multi_technique_chains": sum(
            1
            for c in chains
            if c["num_unique_techniques"] >= 2
        ),

        "unique_techniques": len(
            technique_counter
        ),

        "technique_frequency": dict(
            technique_counter
        ),

        "average_prediction_confidence": (
            sum(
                c["average_confidence"]
                for c in chains
            )
            / len(chains)
            if chains
            else 0
        )
    }

    with open(
        stats_path,
        "w"
    ) as f:

        json.dump(
            stats,
            f,
            indent=4
        )

    return (
        json_path,
        csv_path,
        stats_path,
        stats
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print(
        "SOCFusion GAT V2 "
        "GRAPH-CONSTRAINED ATTACK-CHAIN RECONSTRUCTION"
    )
    print("=" * 70)

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    raw = load_graph(
        GRAPH_PATH
    )

    predictions = load_predictions(
        PREDICTIONS_PATH
    )

    # --------------------------------------------------------
    # Relationships
    # --------------------------------------------------------

    (
        num_events,
        event_host,
        event_user,
        event_processes,
        process_children,
        precedes
    ) = build_event_relationships(raw)

    print()
    print("=" * 70)
    print("RELATIONSHIPS")
    print("=" * 70)

    print(
        f"Events: {num_events}"
    )

    print(
        f"Events with host: "
        f"{len(event_host)}"
    )

    print(
        f"Events with user: "
        f"{len(event_user)}"
    )

    print(
        f"Events with process: "
        f"{len(event_processes)}"
    )

    print(
        f"PRECEDES edges: "
        f"{len(precedes)}"
    )

    # --------------------------------------------------------
    # Reconstruct
    # --------------------------------------------------------

    candidate_chains = reconstruct_chains(
        num_events,
        event_host,
        event_user,
        event_processes,
        process_children,
        precedes,
        predictions
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    chains = validate_chains(
        candidate_chains,
        event_host,
        event_user,
        event_processes,
        predictions
    )

    # --------------------------------------------------------
    # Sort longest first
    # --------------------------------------------------------

    chains.sort(
        key=lambda x: (
            x["num_unique_techniques"],
            x["num_events"],
            x["average_confidence"]
        ),
        reverse=True
    )

    # Renumber IDs after sorting.

    for i, chain in enumerate(
        chains,
        start=1
    ):

        chain["chain_id"] = (
            f"GATV2_CHAIN_{i:06d}"
        )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    (
        json_path,
        csv_path,
        stats_path,
        stats
    ) = save_results(
        chains,
        predictions,
        event_host,
        event_user,
        event_processes
    )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RECONSTRUCTION COMPLETE")
    print("=" * 70)

    print(
        f"Candidate chains : "
        f"{len(candidate_chains)}"
    )

    print(
        f"Final chains     : "
        f"{stats['total_chains']}"
    )

    print(
        f"Events in chains : "
        f"{stats['total_events']}"
    )

    print(
        f"Average length   : "
        f"{stats['average_chain_length']:.2f}"
    )

    print(
        f"Maximum length   : "
        f"{stats['maximum_chain_length']}"
    )

    print(
        f"Multi-technique  : "
        f"{stats['multi_technique_chains']}"
    )

    print(
        f"Unique techniques: "
        f"{stats['unique_techniques']}"
    )

    print(
        f"Average confidence: "
        f"{stats['average_prediction_confidence']:.4f}"
    )

    print()
    print("OUTPUT FILES")
    print("-" * 70)
    print(json_path)
    print(csv_path)
    print(stats_path)

    print()
    print(
        "GAT V2 graph-constrained "
        "attack-chain reconstruction completed."
    )


if __name__ == "__main__":
    main()
