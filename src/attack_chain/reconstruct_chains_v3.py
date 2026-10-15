import os
import csv
import json
from collections import defaultdict, Counter

import torch
import pickle


PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

GRAPH_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/graphs_final_norm/test_data.pt"
)

PREDICTION_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/gat_v2_predictions/test_predictions.csv"
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "data/processed/attack_chains_v3"
)

CHAIN_JSON = os.path.join(
    OUTPUT_DIR,
    "validated_attack_chains.json"
)

CHAIN_EVENTS_CSV = os.path.join(
    OUTPUT_DIR,
    "chain_events.csv"
)

STATISTICS_JSON = os.path.join(
    OUTPUT_DIR,
    "chain_statistics.json"
)


# ------------------------------------------------------------
# PARAMETERS
# ------------------------------------------------------------

# Maximum temporal gap between consecutive events in a chain.
MAX_EVENT_GAP = 500

# Minimum number of DISTINCT techniques required for a
# validated attack chain.
MIN_DISTINCT_TECHNIQUES = 2

# Minimum average confidence for a validated chain.
MIN_CHAIN_CONFIDENCE = 0.35


# ------------------------------------------------------------
# LOAD GRAPH
# ------------------------------------------------------------

def load_graph(path):

    print(f"Loading graph: {path}")

    with open(path, "rb") as f:
        raw = pickle.load(f)

    print("Graph loaded successfully.")

    return raw


# ------------------------------------------------------------
# LOAD PREDICTIONS
# ------------------------------------------------------------

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
        f"Loaded predictions for {len(predictions)} events."
    )

    return predictions


# ------------------------------------------------------------
# EXTRACT RELATIONSHIPS
# ------------------------------------------------------------

def build_relationships(graph):

    nodes = graph["nodes"]
    edges = graph["edges"]

    num_events = nodes["Event"]["num_nodes"]

    event_host = {}
    event_user = {}
    event_process = {}

    # --------------------------------------------------------
    # EVENT -> HOST
    # --------------------------------------------------------

    edge = edges.get(
        ("Event", "RUNS_ON", "Host")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, h in zip(src, dst):

            event_host[int(e)] = int(h)

    # --------------------------------------------------------
    # EVENT -> USER
    # --------------------------------------------------------

    edge = edges.get(
        ("Event", "EXECUTED_BY", "User")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, u in zip(src, dst):

            event_user[int(e)] = int(u)

    # --------------------------------------------------------
    # EVENT -> PROCESS
    # --------------------------------------------------------

    edge = edges.get(
        ("Event", "INVOLVES", "Process")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, p in zip(src, dst):

            event_process[int(e)] = int(p)

    # --------------------------------------------------------
    # PRECEDES
    # --------------------------------------------------------

    precedes = []

    edge = edges.get(
        ("Event", "PRECEDES", "Event")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for a, b in zip(src, dst):

            precedes.append(
                (int(a), int(b))
            )

    print()
    print("=" * 70)
    print("RELATIONSHIPS")
    print("=" * 70)

    print(f"Events: {num_events}")
    print(f"Events with host: {len(event_host)}")
    print(f"Events with user: {len(event_user)}")
    print(f"Events with process: {len(event_process)}")
    print(f"PRECEDES edges: {len(precedes)}")

    return (
        event_host,
        event_user,
        event_process,
        precedes
    )


# ------------------------------------------------------------
# BUILD TEMPORAL CHAINS
# ------------------------------------------------------------

def build_candidates(
    predictions,
    event_host,
    event_process,
    precedes
):

    # --------------------------------------------------------
    # PRECEDES GRAPH
    # --------------------------------------------------------

    successors = defaultdict(list)

    for src, dst in precedes:

        successors[src].append(dst)

    # --------------------------------------------------------
    # GROUP EVENTS BY HOST
    # --------------------------------------------------------

    host_events = defaultdict(list)

    for event_id in predictions:

        host = event_host.get(
            event_id,
            -1
        )

        host_events[host].append(event_id)

    candidates = []

    # --------------------------------------------------------
    # PROCESS EACH HOST
    # --------------------------------------------------------

    for host, events in host_events.items():

        events.sort()

        current = []

        for event_id in events:

            if not current:

                current = [event_id]
                continue

            previous = current[-1]

            temporal_gap = event_id - previous

            connected = (
                event_id in successors.get(
                    previous,
                    []
                )
            )

            same_process = (
                event_process.get(event_id, -1)
                == event_process.get(previous, -2)
                and event_process.get(event_id, -1) != -1
            )

            # ------------------------------------------------
            # CONNECTION RULE
            #
            # Strong connection:
            #   PRECEDES
            #
            # Secondary connection:
            #   same process + temporal proximity
            #
            # Fallback:
            #   temporal proximity on same host
            # ------------------------------------------------

            should_connect = (
                connected
                or
                (
                    same_process
                    and temporal_gap <= MAX_EVENT_GAP
                )
                or
                (
                    temporal_gap <= MAX_EVENT_GAP
                )
            )

            if should_connect:

                current.append(event_id)

            else:

                if len(current) >= 2:
                    candidates.append(current)

                current = [event_id]

        if len(current) >= 2:
            candidates.append(current)

    return candidates


# ------------------------------------------------------------
# REMOVE CONSECUTIVE DUPLICATE TECHNIQUES
# ------------------------------------------------------------

def collapse_techniques(events, predictions):

    sequence = []

    previous = None

    for event_id in events:

        technique = predictions[event_id][
            "predicted_technique"
        ]

        if technique != previous:

            sequence.append(technique)

            previous = technique

    return sequence


# ------------------------------------------------------------
# VALIDATE CANDIDATE
# ------------------------------------------------------------

def validate_candidate(
    events,
    predictions,
    event_host,
    event_user,
    event_process
):

    techniques = [
        predictions[e]["predicted_technique"]
        for e in events
    ]

    unique_techniques = list(
        dict.fromkeys(techniques)
    )

    collapsed_sequence = collapse_techniques(
        events,
        predictions
    )

    confidences = [
        predictions[e]["confidence"]
        for e in events
    ]

    avg_confidence = (
        sum(confidences)
        / len(confidences)
    )

    # --------------------------------------------------------
    # VALIDATION
    # --------------------------------------------------------

    if len(unique_techniques) < MIN_DISTINCT_TECHNIQUES:
        return None

    if avg_confidence < MIN_CHAIN_CONFIDENCE:
        return None

    # --------------------------------------------------------
    # HOST
    # --------------------------------------------------------

    hosts = [
        event_host.get(e, -1)
        for e in events
    ]

    hosts = [
        h for h in hosts
        if h != -1
    ]

    host = (
        Counter(hosts).most_common(1)[0][0]
        if hosts
        else -1
    )

    # --------------------------------------------------------
    # USER
    # --------------------------------------------------------

    users = [
        event_user.get(e, -1)
        for e in events
    ]

    users = [
        u for u in users
        if u != -1
    ]

    user = (
        Counter(users).most_common(1)[0][0]
        if users
        else -1
    )

    # --------------------------------------------------------
    # PROCESSES
    # --------------------------------------------------------

    processes = sorted(
        set(
            event_process.get(e, -1)
            for e in events
            if event_process.get(e, -1) != -1
        )
    )

    return {
        "num_events": len(events),

        "events": events,

        "techniques": techniques,

        "collapsed_techniques": collapsed_sequence,

        "unique_techniques": unique_techniques,

        "num_unique_techniques": len(
            unique_techniques
        ),

        "average_confidence": avg_confidence,

        "min_confidence": min(confidences),

        "max_confidence": max(confidences),

        "host": host,

        "user": user,

        "processes": processes
    }


# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------

def main():

    print("=" * 70)
    print("SOCFusion GAT V2 VALIDATED ATTACK-CHAIN RECONSTRUCTION")
    print("=" * 70)

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    graph = load_graph(
        GRAPH_PATH
    )

    predictions = load_predictions(
        PREDICTION_PATH
    )

    (
        event_host,
        event_user,
        event_process,
        precedes
    ) = build_relationships(graph)

    print()
    print("=" * 70)
    print("BUILDING CANDIDATE CHAINS")
    print("=" * 70)

    candidates = build_candidates(
        predictions,
        event_host,
        event_process,
        precedes
    )

    print(
        f"Candidate chains: {len(candidates)}"
    )

    # --------------------------------------------------------
    # VALIDATE
    # --------------------------------------------------------

    validated = []

    for candidate in candidates:

        result = validate_candidate(
            candidate,
            predictions,
            event_host,
            event_user,
            event_process
        )

        if result is not None:
            validated.append(result)

    # --------------------------------------------------------
    # SORT
    # --------------------------------------------------------

    validated.sort(
        key=lambda x: (
            x["num_unique_techniques"],
            x["num_events"],
            x["average_confidence"]
        ),
        reverse=True
    )

    # --------------------------------------------------------
    # ASSIGN IDS
    # --------------------------------------------------------

    final_chains = []

    for index, chain in enumerate(
        validated,
        start=1
    ):

        chain["chain_id"] = (
            f"GATV2_VALIDATED_{index:06d}"
        )

        # Keep ID first when serialized.
        ordered = {
            "chain_id": chain.pop("chain_id"),
            **chain
        }

        final_chains.append(
            ordered
        )

    # --------------------------------------------------------
    # SAVE JSON
    # --------------------------------------------------------

    with open(
        CHAIN_JSON,
        "w"
    ) as f:

        json.dump(
            final_chains,
            f,
            indent=4
        )

    # --------------------------------------------------------
    # SAVE CSV
    # --------------------------------------------------------

    with open(
        CHAIN_EVENTS_CSV,
        "w",
        newline=""
    ) as f:

        fieldnames = [
            "chain_id",
            "event_index",
            "predicted_class",
            "predicted_technique",
            "confidence",
            "host",
            "user",
            "processes"
        ]

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames
        )

        writer.writeheader()

        for chain in final_chains:

            for event_id in chain["events"]:

                prediction = predictions[
                    event_id
                ]

                writer.writerow({
                    "chain_id":
                        chain["chain_id"],

                    "event_index":
                        event_id,

                    "predicted_class":
                        prediction[
                            "predicted_class"
                        ],

                    "predicted_technique":
                        prediction[
                            "predicted_technique"
                        ],

                    "confidence":
                        prediction[
                            "confidence"
                        ],

                    "host":
                        chain["host"],

                    "user":
                        chain["user"],

                    "processes":
                        ",".join(
                            map(
                                str,
                                chain["processes"]
                            )
                        )
                })

    # --------------------------------------------------------
    # STATISTICS
    # --------------------------------------------------------

    lengths = Counter()

    technique_counts = Counter()

    total_events = 0

    total_confidence = 0.0

    for chain in final_chains:

        lengths[
            chain["num_events"]
        ] += 1

        total_events += chain[
            "num_events"
        ]

        total_confidence += chain[
            "average_confidence"
        ]

        for technique in chain[
            "unique_techniques"
        ]:

            technique_counts[
                technique
            ] += 1

    total_chains = len(
        final_chains
    )

    statistics = {

        "candidate_chains":
            len(candidates),

        "validated_chains":
            total_chains,

        "events_in_validated_chains":
            total_events,

        "minimum_chain_length":
            min(
                [c["num_events"] for c in final_chains],
                default=0
            ),

        "maximum_chain_length":
            max(
                [c["num_events"] for c in final_chains],
                default=0
            ),

        "average_chain_length":
            (
                total_events / total_chains
                if total_chains
                else 0
            ),

        "average_chain_confidence":
            (
                total_confidence / total_chains
                if total_chains
                else 0
            ),

        "unique_techniques":
            len(technique_counts),

        "technique_frequency":
            dict(
                technique_counts.most_common()
            ),

        "configuration": {
            "max_event_gap":
                MAX_EVENT_GAP,

            "minimum_distinct_techniques":
                MIN_DISTINCT_TECHNIQUES,

            "minimum_chain_confidence":
                MIN_CHAIN_CONFIDENCE
        }
    }

    with open(
        STATISTICS_JSON,
        "w"
    ) as f:

        json.dump(
            statistics,
            f,
            indent=4
        )

    # --------------------------------------------------------
    # REPORT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RECONSTRUCTION COMPLETE")
    print("=" * 70)

    print(
        f"Candidate chains : {len(candidates)}"
    )

    print(
        f"Validated chains : {total_chains}"
    )

    print(
        f"Events in chains : {total_events}"
    )

    print(
        f"Average length   : "
        f"{statistics['average_chain_length']:.2f}"
    )

    print(
        f"Maximum length   : "
        f"{statistics['maximum_chain_length']}"
    )

    print(
        f"Unique techniques: "
        f"{statistics['unique_techniques']}"
    )

    print(
        f"Average confidence: "
        f"{statistics['average_chain_confidence']:.4f}"
    )

    print()
    print("OUTPUT FILES")
    print("-" * 70)

    print(CHAIN_JSON)
    print(CHAIN_EVENTS_CSV)
    print(STATISTICS_JSON)

    print()
    print(
        "GAT V2 validated attack-chain reconstruction completed."
    )


if __name__ == "__main__":
    main()
