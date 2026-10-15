import os
import csv
import json
import pickle
from collections import defaultdict, deque

import numpy as np


# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

GRAPH_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/graphs_final_norm/test_data.pt"
)

PREDICTIONS_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/gat_v2_predictions/test_predictions.csv"
)

EMBEDDINGS_PATH = os.path.join(
    PROJECT_ROOT,
    "data/processed/gat_v2_predictions/test_embeddings.pt"
)

OUTPUT_DIR = os.path.join(
    PROJECT_ROOT,
    "data/processed/attack_chains_v2"
)

CHAINS_JSON = os.path.join(
    OUTPUT_DIR,
    "reconstructed_chains.json"
)

CHAIN_EVENTS_CSV = os.path.join(
    OUTPUT_DIR,
    "chain_events.csv"
)

CHAIN_STATS_JSON = os.path.join(
    OUTPUT_DIR,
    "chain_statistics.json"
)


# ============================================================
# RECONSTRUCTION PARAMETERS
# ============================================================

# Minimum cosine similarity for two events to be considered
# semantically related.
SIMILARITY_THRESHOLD = 0.85

# Maximum number of PRECEDES hops allowed when extending
# a chain.
MAX_TEMPORAL_GAP = 5

# A valid chain must contain at least this many events.
MIN_CHAIN_LENGTH = 2


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
# LOAD GAT V2 PREDICTIONS
# ============================================================

def load_predictions(path):

    print(f"Loading predictions: {path}")

    predictions = {}

    with open(path, "r", newline="") as f:

        reader = csv.DictReader(f)

        for row in reader:

            event_index = int(
                row["event_index"]
            )

            predictions[event_index] = {
                "predicted_class": int(
                    row["predicted_class"]
                ),
                "predicted_technique":
                    row["predicted_technique"],
                "confidence": float(
                    row["confidence"]
                )
            }

    print(
        f"Loaded predictions for "
        f"{len(predictions)} events."
    )

    return predictions


# ============================================================
# LOAD EMBEDDINGS
# ============================================================

def load_embeddings(path):

    print(f"Loading embeddings: {path}")

    import torch

    embeddings = torch.load(
        path,
        map_location="cpu",
        weights_only=True
    )

    embeddings = embeddings.numpy()

    print(
        f"Embeddings shape: "
        f"{embeddings.shape}"
    )

    return embeddings


# ============================================================
# COSINE SIMILARITY
# ============================================================

def cosine_similarity(a, b):

    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return float(
        np.dot(a, b) /
        (norm_a * norm_b)
    )


# ============================================================
# BUILD EVENT RELATIONSHIPS
# ============================================================

def build_relationships(raw):

    edges = raw["edges"]

    num_events = raw["nodes"]["Event"]["num_nodes"]

    # --------------------------------------------------------
    # Event -> Host
    # --------------------------------------------------------

    event_host = {}

    edge = edges.get(
        ("Event", "RUNS_ON", "Host")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, h in zip(src, dst):

            event_host[int(e)] = int(h)

    # --------------------------------------------------------
    # Event -> User
    # --------------------------------------------------------

    event_user = {}

    edge = edges.get(
        ("Event", "EXECUTED_BY", "User")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, u in zip(src, dst):

            event_user[int(e)] = int(u)

    # --------------------------------------------------------
    # Event -> Process
    # --------------------------------------------------------

    event_processes = defaultdict(set)

    edge = edges.get(
        ("Event", "INVOLVES", "Process")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e, p in zip(src, dst):

            event_processes[int(e)].add(
                int(p)
            )

    # --------------------------------------------------------
    # PRECEDES
    # --------------------------------------------------------

    precedes = defaultdict(list)

    edge = edges.get(
        ("Event", "PRECEDES", "Event")
    )

    if edge:

        src = edge["edge_index"][0]
        dst = edge["edge_index"][1]

        for e1, e2 in zip(src, dst):

            precedes[int(e1)].append(
                int(e2)
            )

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
        f"{sum(len(v) for v in precedes.values())}"
    )

    return (
        event_host,
        event_user,
        event_processes,
        precedes
    )


# ============================================================
# EVENT RELATION SCORE
# ============================================================

def relation_score(
    event_a,
    event_b,
    event_host,
    event_user,
    event_processes,
    embeddings
):

    score = 0.0

    # Same host
    if (
        event_a in event_host
        and event_b in event_host
        and event_host[event_a]
        == event_host[event_b]
    ):
        score += 0.35

    # Same user
    if (
        event_a in event_user
        and event_b in event_user
        and event_user[event_a]
        == event_user[event_b]
    ):
        score += 0.20

    # Same process
    if (
        event_a in event_processes
        and event_b in event_processes
        and event_processes[event_a]
        & event_processes[event_b]
    ):
        score += 0.30

    # Embedding similarity
    similarity = cosine_similarity(
        embeddings[event_a],
        embeddings[event_b]
    )

    if similarity >= SIMILARITY_THRESHOLD:

        # Scale similarity contribution
        # from 0.15 to 0.30.
        score += 0.15 + (
            0.15 *
            (
                (similarity -
                 SIMILARITY_THRESHOLD)
                /
                (1.0 -
                 SIMILARITY_THRESHOLD)
            )
        )

    return score, similarity


# ============================================================
# BUILD CHAINS
# ============================================================

def reconstruct_chains(
    raw,
    predictions,
    embeddings
):

    (
        event_host,
        event_user,
        event_processes,
        precedes
    ) = build_relationships(raw)

    num_events = raw["nodes"]["Event"]["num_nodes"]

    # --------------------------------------------------------
    # Reverse PRECEDES index
    # --------------------------------------------------------

    predecessors = defaultdict(list)

    for source, destinations in precedes.items():

        for destination in destinations:

            predecessors[destination].append(
                source
            )

    # --------------------------------------------------------
    # Track assigned events
    # --------------------------------------------------------

    assigned = set()

    chains = []

    # Process events in chronological/index order.
    for start_event in range(num_events):

        if start_event in assigned:
            continue

        if start_event not in predictions:
            continue

        chain = [
            start_event
        ]

        chain_set = {
            start_event
        }

        queue = deque([
            (
                start_event,
                0
            )
        ])

        while queue:

            current, depth = queue.popleft()

            if depth >= MAX_TEMPORAL_GAP:
                continue

            # ------------------------------------------------
            # Forward PRECEDES edges
            # ------------------------------------------------

            candidates = precedes.get(
                current,
                []
            )

            for candidate in candidates:

                if candidate in chain_set:
                    continue

                if candidate not in predictions:
                    continue

                score, similarity = relation_score(
                    current,
                    candidate,
                    event_host,
                    event_user,
                    event_processes,
                    embeddings
                )

                # Strong relationship:
                # temporal edge + contextual relation.
                if score >= 0.20:

                    chain.append(candidate)

                    chain_set.add(candidate)

                    queue.append(
                        (
                            candidate,
                            depth + 1
                        )
                    )

            # ------------------------------------------------
            # Backward PRECEDES edges
            # ------------------------------------------------

            candidates = predecessors.get(
                current,
                []
            )

            for candidate in candidates:

                if candidate in chain_set:
                    continue

                if candidate not in predictions:
                    continue

                score, similarity = relation_score(
                    candidate,
                    current,
                    event_host,
                    event_user,
                    event_processes,
                    embeddings
                )

                if score >= 0.20:

                    chain.append(candidate)

                    chain_set.add(candidate)

                    queue.append(
                        (
                            candidate,
                            depth + 1
                        )
                    )

        # ----------------------------------------------------
        # Finalize chain
        # ----------------------------------------------------

        chain = sorted(
            chain
        )

        if len(chain) >= MIN_CHAIN_LENGTH:

            chains.append(
                chain
            )

            assigned.update(
                chain
            )

    return chains


# ============================================================
# BUILD OUTPUT
# ============================================================

def build_outputs(
    chains,
    predictions,
    event_host,
    event_user,
    event_processes
):

    records = []

    chain_event_rows = []

    technique_counts = defaultdict(int)

    confidence_values = []

    for chain_number, events in enumerate(
        chains,
        start=1
    ):

        chain_id = (
            f"GATV2_CHAIN_{chain_number:06d}"
        )

        chain_techniques = []

        for event_index in events:

            prediction = predictions[
                event_index
            ]

            technique = prediction[
                "predicted_technique"
            ]

            confidence = prediction[
                "confidence"
            ]

            chain_techniques.append(
                technique
            )

            technique_counts[
                technique
            ] += 1

            confidence_values.append(
                confidence
            )

            chain_event_rows.append({

                "chain_id":
                    chain_id,

                "event_index":
                    event_index,

                "predicted_class":
                    prediction[
                        "predicted_class"
                    ],

                "predicted_technique":
                    technique,

                "confidence":
                    confidence,

                "host":
                    event_host.get(
                        event_index,
                        -1
                    ),

                "user":
                    event_user.get(
                        event_index,
                        -1
                    ),

                "processes":
                    ",".join(
                        map(
                            str,
                            sorted(
                                event_processes.get(
                                    event_index,
                                    set()
                                )
                            )
                        )
                    )
            })

        records.append({

            "chain_id":
                chain_id,

            "num_events":
                len(events),

            "events":
                events,

            "techniques":
                chain_techniques,

            "unique_techniques":
                sorted(
                    set(
                        chain_techniques
                    )
                )
        })

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    all_chain_events = sum(
        len(chain)
        for chain in chains
    )

    stats = {

        "total_chains":
            len(chains),

        "total_events":
            all_chain_events,

        "minimum_chain_length":
            min(
                (
                    len(c)
                    for c in chains
                ),
                default=0
            ),

        "maximum_chain_length":
            max(
                (
                    len(c)
                    for c in chains
                ),
                default=0
            ),

        "average_chain_length":
            (
                all_chain_events /
                len(chains)
                if chains
                else 0
            ),

        "unique_techniques":
            len(technique_counts),

        "technique_frequency":
            dict(
                sorted(
                    technique_counts.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            ),

        "average_prediction_confidence":
            (
                float(
                    np.mean(
                        confidence_values
                    )
                )
                if confidence_values
                else 0.0
            )
    }

    return (
        records,
        chain_event_rows,
        stats
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)
    print("SOCFusion GAT V2 ATTACK-CHAIN RECONSTRUCTION")
    print("=" * 70)

    os.makedirs(
        OUTPUT_DIR,
        exist_ok=True
    )

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    raw = load_graph(
        GRAPH_PATH
    )

    predictions = load_predictions(
        PREDICTIONS_PATH
    )

    embeddings = load_embeddings(
        EMBEDDINGS_PATH
    )

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    num_events = raw[
        "nodes"
    ][
        "Event"
    ][
        "num_nodes"
    ]

    if len(predictions) != num_events:

        raise RuntimeError(
            f"Prediction count mismatch: "
            f"{len(predictions)} predictions "
            f"for {num_events} events."
        )

    if embeddings.shape[0] != num_events:

        raise RuntimeError(
            f"Embedding count mismatch: "
            f"{embeddings.shape[0]} embeddings "
            f"for {num_events} events."
        )

    # --------------------------------------------------------
    # Reconstruct
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RECONSTRUCTING ATTACK CHAINS")
    print("=" * 70)

    chains = reconstruct_chains(
        raw,
        predictions,
        embeddings
    )

    print()
    print(
        f"Valid chains reconstructed: "
        f"{len(chains)}"
    )

    # --------------------------------------------------------
    # Build outputs
    # --------------------------------------------------------

    (
        event_host,
        event_user,
        event_processes,
        _
    ) = build_relationships(
        raw
    )

    (
        records,
        chain_event_rows,
        stats
    ) = build_outputs(
        chains,
        predictions,
        event_host,
        event_user,
        event_processes
    )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    with open(
        CHAINS_JSON,
        "w"
    ) as f:

        json.dump(
            records,
            f,
            indent=4
        )

    # --------------------------------------------------------
    # CSV
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

        writer.writerows(
            chain_event_rows
        )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    with open(
        CHAIN_STATS_JSON,
        "w"
    ) as f:

        json.dump(
            stats,
            f,
            indent=4
        )

    # --------------------------------------------------------
    # Final report
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RECONSTRUCTION COMPLETE")
    print("=" * 70)

    print(
        f"Chains: "
        f"{stats['total_chains']}"
    )

    print(
        f"Events in chains: "
        f"{stats['total_events']}"
    )

    print(
        f"Average chain length: "
        f"{stats['average_chain_length']:.2f}"
    )

    print(
        f"Maximum chain length: "
        f"{stats['maximum_chain_length']}"
    )

    print(
        f"Unique techniques: "
        f"{stats['unique_techniques']}"
    )

    print()
    print("OUTPUT FILES")
    print("-" * 70)

    print(
        CHAINS_JSON
    )

    print(
        CHAIN_EVENTS_CSV
    )

    print(
        CHAIN_STATS_JSON
    )

    print()
    print(
        "GAT V2 attack-chain reconstruction "
        "completed successfully."
    )


if __name__ == "__main__":
    main()
