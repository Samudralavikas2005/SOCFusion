import os
import sys
import json
import csv
import pickle

import torch

# Allow imports from project root
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../..")
)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from torch_geometric.data import HeteroData

from src.models.deployment.gat import SOCFusionGAT


class GATV2Inference:

    def __init__(self, model_dir=None, device=None):

        if model_dir is None:
            model_dir = os.path.dirname(
                os.path.abspath(__file__)
            )

        self.model_dir = model_dir

        self.checkpoint_path = os.path.join(
            PROJECT_ROOT,
            "data/processed/gat_v2/checkpoints/best_model.pth"
        )

        self.config_path = os.path.join(
            model_dir,
            "training_config.json"
        )

        self.device = torch.device(
            device
            if device
            else (
                "cuda"
                if torch.cuda.is_available()
                else "cpu"
            )
        )

        # Model architecture
        self.hidden_dim = 64
        self.num_heads = 4
        self.num_classes = 15

        self.num_hosts = 62
        self.num_users = 65
        self.num_processes = 2235

        self.edge_types = [
            ("Event", "RUNS_ON", "Host"),
            ("Event", "EXECUTED_BY", "User"),
            ("Event", "INVOLVES", "Process"),
            ("Process", "SPAWNED", "Process"),
            ("Event", "PRECEDES", "Event"),
            ("Host", "rev_RUNS_ON", "Event"),
            ("User", "rev_EXECUTED_BY", "Event"),
            ("Process", "rev_INVOLVES", "Event"),
        ]

        self.model = SOCFusionGAT(
            hidden_dim=self.hidden_dim,
            num_heads=self.num_heads,
            num_classes=self.num_classes,
            edge_types=self.edge_types,
            num_hosts=self.num_hosts,
            num_users=self.num_users,
            num_processes=self.num_processes
        )

        print(
            f"Loading GAT V2 checkpoint: "
            f"{self.checkpoint_path}"
        )

        state_dict = torch.load(
            self.checkpoint_path,
            map_location=self.device,
            weights_only=True
        )

        self.model.load_state_dict(state_dict)

        self.model.to(self.device)
        self.model.eval()

        self.label_mapping = self._load_label_mapping()

        print("GAT V2 loaded successfully.")
        print(f"Device: {self.device}")
        print(f"Classes: {self.num_classes}")

    def _load_label_mapping(self):

        path = os.path.join(
            PROJECT_ROOT,
            "data/processed/graphs_final/label_mapping.json"
        )

        if not os.path.exists(path):
            return {}

        with open(path, "r") as f:
            mapping = json.load(f)

        return {
            int(v): k
            for k, v in mapping.items()
        }

    def predict(self, data):

        data = data.to(self.device)

        with torch.no_grad():

            logits, embeddings = self.model(
                data.x_dict,
                data.edge_index_dict
            )

            probabilities = torch.softmax(
                logits,
                dim=-1
            )

            predictions = torch.argmax(
                probabilities,
                dim=-1
            )

        return (
            predictions,
            probabilities,
            embeddings
        )

    def predict_events(self, data):

        predictions, probabilities, embeddings = (
            self.predict(data)
        )

        results = []

        for i in range(predictions.shape[0]):

            class_idx = int(
                predictions[i].item()
            )

            result = {
                "event_index": i,

                "predicted_class": class_idx,

                "predicted_technique":
                    self.label_mapping.get(
                        class_idx,
                        str(class_idx)
                    ),

                "confidence": float(
                    probabilities[
                        i,
                        class_idx
                    ].item()
                )
            }

            results.append(result)

        return results, embeddings


def load_graph(path):

    with open(path, "rb") as f:
        raw = pickle.load(f)

    data = HeteroData()

    # ========================================================
    # NODES
    # ========================================================

    for node_type, node_data in raw["nodes"].items():

        if "x" in node_data:

            data[node_type].x = torch.tensor(
                node_data["x"],
                dtype=torch.float32
            )

        data[node_type].num_nodes = (
            node_data["num_nodes"]
        )

        # Host/User/Process do not contain feature matrices.
        # The trained GAT creates their embeddings internally.
        if "x" not in node_data:

            data[node_type].x = torch.empty(
                (
                    node_data["num_nodes"],
                    0
                ),
                dtype=torch.float32
            )

        if "y" in node_data:

            data[node_type].y = torch.tensor(
                node_data["y"],
                dtype=torch.long
            )

    # ========================================================
    # EDGES
    # ========================================================

    for edge_type, edge_data in raw["edges"].items():

        data[edge_type].edge_index = torch.tensor(
            edge_data["edge_index"],
            dtype=torch.long
        )

    # ========================================================
    # REVERSE EDGES
    # ========================================================

    reverse_map = {

        ("Event", "RUNS_ON", "Host"):
            ("Host", "rev_RUNS_ON", "Event"),

        ("Event", "EXECUTED_BY", "User"):
            ("User", "rev_EXECUTED_BY", "Event"),

        ("Event", "INVOLVES", "Process"):
            ("Process", "rev_INVOLVES", "Event"),
    }

    for original, reverse in reverse_map.items():

        if original not in data.edge_types:
            continue

        edge_index = data[original].edge_index

        data[reverse].edge_index = torch.stack(
            [
                edge_index[1],
                edge_index[0]
            ],
            dim=0
        )

    return data


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("SOCFusion GAT V2 INFERENCE TEST")
    print("=" * 70)

    # ========================================================
    # LOAD MODEL
    # ========================================================

    model = GATV2Inference()

    # ========================================================
    # LOAD TEST GRAPH
    # ========================================================

    test_path = (
        "data/processed/graphs_final_norm/"
        "test_data.pt"
    )

    print(
        f"\nLoading: {test_path}"
    )

    data = load_graph(test_path)

    print(
        f"Events: "
        f"{data['Event'].num_nodes}"
    )

    print(
        f"Features: "
        f"{data['Event'].x.shape}"
    )

    # ========================================================
    # RUN INFERENCE
    # ========================================================

    results, embeddings = (
        model.predict_events(data)
    )

    # ========================================================
    # INFERENCE RESULTS
    # ========================================================

    print("\n" + "=" * 70)
    print("INFERENCE SUCCESS")
    print("=" * 70)

    print(
        f"Predictions: "
        f"{len(results)}"
    )

    print(
        f"Embeddings: "
        f"{embeddings.shape}"
    )

    # ========================================================
    # FIRST 10 PREDICTIONS
    # ========================================================

    print("\nFirst 10 predictions:")

    for result in results[:10]:
        print(result)

    # ========================================================
    # SAVE PREDICTIONS
    # ========================================================

    output_dir = (
        "data/processed/gat_v2_predictions"
    )

    os.makedirs(
        output_dir,
        exist_ok=True
    )

    output_path = os.path.join(
        output_dir,
        "test_predictions.csv"
    )

    with open(
        output_path,
        "w",
        newline=""
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=[
                "event_index",
                "predicted_class",
                "predicted_technique",
                "confidence"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    print(
        f"\nPredictions saved to: "
        f"{output_path}"
    )

    # ========================================================
    # SAVE EMBEDDINGS
    # ========================================================

    embedding_path = os.path.join(
        output_dir,
        "test_embeddings.pt"
    )

    torch.save(
        embeddings.cpu(),
        embedding_path
    )

    print(
        f"Embeddings saved to: "
        f"{embedding_path}"
    )

    # ========================================================
    # FINAL STATUS
    # ========================================================

    print(
        "\nGAT V2 deployment model is working."
    )
