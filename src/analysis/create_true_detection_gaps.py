import os
import json
import pickle
import numpy as np
import pandas as pd

from sklearn.metrics import confusion_matrix

BASE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

GRAPH_PATH = os.path.join(
    BASE,
    "data/processed/graphs_final_norm/test_data.pt"
)

PREDICTIONS_PATH = os.path.join(
    BASE,
    "data/processed/gat_v2_predictions/test_predictions.csv"
)

ANALYSIS_DIR = os.path.join(
    BASE,
    "data/analysis/detection_gaps"
)

DASHBOARD_DIR = os.path.join(
    BASE,
    "data/processed/dashboard"
)

os.makedirs(ANALYSIS_DIR, exist_ok=True)
os.makedirs(DASHBOARD_DIR, exist_ok=True)


# ============================================================
# GAT V2 TRACK-A CLASSES
# ============================================================

TRACK_A = [
    0,
    1,
    2,
    4,
    5,
    6,
    7,
    10,
    11,
    12,
    13,
    14
]

LABEL_MAP = {
    0: "T1003.001",
    1: "T1003.003",
    2: "T1016",
    3: "T1018",
    4: "T1021.006",
    5: "T1047",
    6: "T1053.005",
    7: "T1059.001",
    8: "T1059.003",
    9: "T1068",
    10: "T1087.002",
    11: "T1105",
    12: "T1112",
    13: "T1558.003",
    14: "T1562.001"
}


print("=" * 70)
print("SOCFusion TRUE DETECTION GAP ANALYZER")
print("CURRENT GAT V2 TEST PREDICTIONS")
print("=" * 70)


# ============================================================
# LOAD TEST GRAPH
# ============================================================

print("\nLoading test graph:")
print(GRAPH_PATH)

if not os.path.exists(GRAPH_PATH):
    raise FileNotFoundError(GRAPH_PATH)

with open(GRAPH_PATH, "rb") as f:
    raw = pickle.load(f)

true_labels = np.asarray(
    raw["nodes"]["Event"]["y"],
    dtype=int
)

print(
    f"Ground-truth events available: "
    f"{len(true_labels)}"
)


# ============================================================
# LOAD CURRENT PREDICTIONS
# ============================================================

print("\nLoading CURRENT GAT V2 predictions:")
print(PREDICTIONS_PATH)

if not os.path.exists(PREDICTIONS_PATH):
    raise FileNotFoundError(PREDICTIONS_PATH)

pred_df = pd.read_csv(PREDICTIONS_PATH)

if "predicted_class" not in pred_df.columns:
    raise RuntimeError(
        "predicted_class column missing from predictions CSV."
    )

pred_labels = pred_df["predicted_class"].astype(int).to_numpy()

print(
    f"Predictions available: "
    f"{len(pred_labels)}"
)


# ============================================================
# SAFETY CHECK
# ============================================================

if len(true_labels) != len(pred_labels):
    raise RuntimeError(
        "GROUND TRUTH / PREDICTION LENGTH MISMATCH\n"
        f"Ground truth: {len(true_labels)}\n"
        f"Predictions : {len(pred_labels)}"
    )

print("\nGround truth and predictions MATCH.")


# ============================================================
# FILTER TO TRACK-A GROUND TRUTH
# ============================================================

mask = np.isin(
    true_labels,
    TRACK_A
)

y_true = true_labels[mask]
y_pred = pred_labels[mask]

print(
    f"\nTrack-A ground-truth events: "
    f"{len(y_true)}"
)

print(
    "Excluded Track-B true events: "
    f"{len(true_labels) - len(y_true)}"
)


# ============================================================
# CONFUSION MATRIX
#
# Rows    = ground truth
# Columns = prediction
#
# Only Track-A columns are retained.
# Predictions into Track-B therefore count as misses
# for the corresponding Track-A ground-truth class.
# ============================================================

cm = confusion_matrix(
    y_true,
    y_pred,
    labels=TRACK_A
)

print(
    f"\nConfusion matrix shape: "
    f"{cm.shape}"
)


# ============================================================
# CALCULATE TRUE DETECTION GAPS
# ============================================================

total_track_a_events = int(len(y_true))

rows = []

for i, class_idx in enumerate(TRACK_A):

    technique = LABEL_MAP[class_idx]

    tp = int(cm[i, i])

    fn = int(
        np.sum(
            y_true == class_idx
        ) - tp
    )

    fp = int(
        np.sum(
            y_pred == class_idx
        ) - tp
    )

    tn = int(
        total_track_a_events
        - tp
        - fn
        - fp
    )

    support = tp + fn

    recall = (
        tp / support
        if support
        else 0.0
    )

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    false_negative_rate = (
        fn / support
        if support
        else 0.0
    )

    if false_negative_rate >= 0.80:
        priority = "CRITICAL"
    elif false_negative_rate >= 0.50:
        priority = "HIGH"
    elif false_negative_rate >= 0.20:
        priority = "MEDIUM"
    else:
        priority = "LOW"

    rows.append({
        "technique": technique,
        "support": support,
        "true_positive": tp,
        "false_positive": fp,
        "false_negative": fn,
        "true_negative": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "detection_rate": round(recall, 4),
        "false_negative_rate": round(
            false_negative_rate,
            4
        ),
        "miss_rate": round(
            false_negative_rate,
            4
        ),
        "gap_score": round(
            false_negative_rate,
            4
        ),
        "priority": priority
    })


gaps = pd.DataFrame(rows)

gaps = gaps.sort_values(
    ["false_negative_rate", "support"],
    ascending=[False, False]
).reset_index(drop=True)


# ============================================================
# SAVE CURRENT DETECTION-GAP DATA
# ============================================================

output_csv = os.path.join(
    ANALYSIS_DIR,
    "true_detection_gaps.csv"
)

dashboard_csv = os.path.join(
    DASHBOARD_DIR,
    "true_detection_gaps.csv"
)

gaps.to_csv(
    output_csv,
    index=False
)

gaps.to_csv(
    dashboard_csv,
    index=False
)


# ============================================================
# SAVE CONFUSION MATRIX
# ============================================================

cm_output = os.path.join(
    ANALYSIS_DIR,
    "current_gat_v2_confusion_matrix.csv"
)

np.savetxt(
    cm_output,
    cm,
    delimiter=",",
    fmt="%d"
)


# ============================================================
# SUMMARY
# ============================================================

summary = {
    "model": "GAT V2",
    "evaluation": "current_test_predictions",
    "test_events": int(len(true_labels)),
    "track_a_events": total_track_a_events,
    "track_b_excluded": int(
        len(true_labels) - total_track_a_events
    ),
    "techniques_evaluated": len(gaps),
    "prediction_file": PREDICTIONS_PATH,
    "graph_file": GRAPH_PATH
}

summary_path = os.path.join(
    ANALYSIS_DIR,
    "true_detection_gap_summary.json"
)

with open(summary_path, "w") as f:
    json.dump(
        summary,
        f,
        indent=2
    )


# ============================================================
# PRINT RESULTS
# ============================================================

print("\n" + "=" * 70)
print("CURRENT GAT V2 DETECTION GAP DATASET CREATED")
print("=" * 70)

print(
    f"\nTotal test events : "
    f"{len(true_labels)}"
)

print(
    f"Track-A events    : "
    f"{total_track_a_events}"
)

print(
    f"Track-B excluded  : "
    f"{len(true_labels) - total_track_a_events}"
)

print(
    f"Techniques        : "
    f"{len(gaps)}"
)

print("\nDetection-gap ranking:")

print(
    gaps[
        [
            "technique",
            "support",
            "true_positive",
            "false_negative",
            "precision",
            "recall",
            "f1",
            "false_negative_rate",
            "priority"
        ]
    ].to_string(index=False)
)

print("\nOutput files:")
print(output_csv)
print(dashboard_csv)
print(cm_output)
print(summary_path)

print("\n" + "=" * 70)
print("IMPORTANT")
print("=" * 70)
print("TP/FN are calculated directly from:")
print("  graphs_final_norm/test_data.pt")
print("  gat_v2_predictions/test_predictions.csv")
print("")
print("No old GAT metrics/confusion matrix is used.")
print("")
print("miss_rate = FN / (TP + FN)")
print("=" * 70)
