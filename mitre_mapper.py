import csv
from pathlib import Path
from datetime import datetime


# ============================================================
# CONFIGURATION
# ============================================================

EDGE_FILE = "data/attack_edges.csv"
CHAIN_FILE = "data/attack_chains.txt"
OUTPUT_FILE = "data/mitre_mapping.txt"


# ============================================================
# HELPERS
# ============================================================

def parse_timestamp(value):
    """
    Parse timestamps while preserving timezone information.
    """
    value = value.strip()

    if not value:
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def load_edges():
    """
    Load graph edges from attack_edges.csv.
    """
    edges = []

    with open(EDGE_FILE, newline="") as f:
        reader = csv.DictReader(f)

        for row in reader:
            edges.append({
                "source": row["source"].strip(),
                "target": row["target"].strip(),
                "type": row["edge_type"].strip(),
                "timestamp": row["timestamp"].strip()
            })

    return edges


def format_evidence(edge):
    return (
        f"{edge['timestamp']} | "
        f"{edge['source']} --[{edge['type']}]--> {edge['target']}"
    )


# ============================================================
# LOAD DATA
# ============================================================

print()
print("========== MITRE ATT&CK MAPPING ENGINE ==========")

edges = load_edges()


# ============================================================
# IDENTIFY ATTACK EVIDENCE
# ============================================================

process_create_edges = [
    e for e in edges
    if e["type"] == "PROCESS_CREATE"
]

remote_thread_edges = [
    e for e in edges
    if e["type"] == "REMOTE_THREAD"
]

registry_edges = [
    e for e in edges
    if e["type"] == "REGISTRY_EDIT"
]


# ============================================================
# ATTACK PROCESSES
# ============================================================

attack_processes = set()

for edge in process_create_edges:

    attack_processes.add(edge["source"])
    attack_processes.add(edge["target"])

for edge in remote_thread_edges:

    if edge["source"].startswith("process:"):
        attack_processes.add(edge["source"])

for edge in registry_edges:

    if edge["source"].startswith("process:"):
        attack_processes.add(edge["source"])


print(f"Attack processes : {len(attack_processes)}")
print(f"Process relations: {len(process_create_edges)}")
print(f"Remote threads   : {len(remote_thread_edges)}")
print(f"Registry edits   : {len(registry_edges)}")


# ============================================================
# RECONSTRUCTED ATTACK CHAIN
# ============================================================

print()
print("========== RECONSTRUCTED ATTACK CHAIN ==========")
print()

# Build process-create relationships
children = {}

for edge in process_create_edges:

    source = edge["source"]
    target = edge["target"]

    children.setdefault(source, []).append(edge)


# Find root processes
targets = {
    edge["target"]
    for edge in process_create_edges
}

roots = sorted(
    attack_processes - targets
)


if not roots:
    print("No root process found.")
else:

    for root in roots:

        print(root)

        current = root

        visited = set()

        while current in children:

            if current in visited:
                break

            visited.add(current)

            relations = sorted(
                children[current],
                key=lambda e: (
                    parse_timestamp(e["timestamp"])
                    or datetime.min
                )
            )

            if not relations:
                break

            edge = relations[0]

            print("    |")
            print(f"    | {edge['type']}")
            print("    v")

            current = edge["target"]

            print(current)


# ============================================================
# MITRE TECHNIQUES
# ============================================================

techniques = []


# ------------------------------------------------------------
# T1112 - MODIFY REGISTRY
# ------------------------------------------------------------

if registry_edges:

    evidence = []

    for edge in registry_edges:
        evidence.append(
            f"      - {format_evidence(edge)}"
        )

    techniques.append({
        "id": "T1112",
        "name": "Modify Registry",
        "tactic": "Persistence / Defense Evasion",
        "confidence": "HIGH",
        "evidence": evidence,
        "limitation": (
            "Registry modification is directly observed, but "
            "the specific registry key/purpose is not available "
            "in the retained graph."
        )
    })


# ------------------------------------------------------------
# T1055 - PROCESS INJECTION
#
# IMPORTANT:
# All REMOTE_THREAD observations are aggregated into ONE
# T1055 technique instead of creating duplicate entries.
# ------------------------------------------------------------

if remote_thread_edges:

    evidence = []

    for edge in remote_thread_edges:

        evidence.append(
            f"      - {format_evidence(edge)}"
        )

    techniques.append({
        "id": "T1055",
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
        "confidence": "LOW",
        "evidence": evidence,
        "limitation": (
            "REMOTE_THREAD behavior is observed, but the "
            "retained graph does not contain sufficient evidence "
            "to confirm a specific Process Injection sub-technique."
        )
    })


# ============================================================
# PRINT MITRE RESULTS
# ============================================================

print()
print("========== MITRE ATT&CK TECHNIQUES ==========")
print()

if not techniques:

    print("No MITRE ATT&CK techniques identified.")

else:

    for index, technique in enumerate(techniques, start=1):

        print(
            f"[{index}] "
            f"{technique['id']} - "
            f"{technique['name']}"
        )

        print(
            f"    Tactic     : "
            f"{technique['tactic']}"
        )

        print(
            f"    Confidence : "
            f"{technique['confidence']}"
        )

        print("    Evidence:")

        for evidence in technique["evidence"]:
            print(evidence)

        print("    Limitation:")
        print(
            f"      {technique['limitation']}"
        )

        print()


# ============================================================
# SAVE MITRE REPORT
# ============================================================

output = []

output.append(
    "========== MITRE ATT&CK MAPPING ENGINE =========="
)

output.append("")

output.append(
    f"Attack processes : {len(attack_processes)}"
)

output.append(
    f"Process relations: {len(process_create_edges)}"
)

output.append(
    f"Remote threads   : {len(remote_thread_edges)}"
)

output.append(
    f"Registry edits   : {len(registry_edges)}"
)

output.append("")

output.append(
    "========== RECONSTRUCTED ATTACK CHAIN =========="
)

output.append("")


# Save roots and process lineage
if roots:

    for root in roots:

        output.append(root)

        current = root
        visited = set()

        while current in children:

            if current in visited:
                break

            visited.add(current)

            relations = sorted(
                children[current],
                key=lambda e: (
                    parse_timestamp(e["timestamp"])
                    or datetime.min
                )
            )

            if not relations:
                break

            edge = relations[0]

            output.append("    |")
            output.append(
                f"    | {edge['type']}"
            )
            output.append("    v")

            current = edge["target"]

            output.append(current)

else:

    output.append(
        "No reconstructed process chain."
    )


output.append("")
output.append(
    "========== MITRE ATT&CK TECHNIQUES =========="
)
output.append("")


if not techniques:

    output.append(
        "No MITRE ATT&CK techniques identified."
    )

else:

    for index, technique in enumerate(techniques, start=1):

        output.append(
            f"[{index}] "
            f"{technique['id']} - "
            f"{technique['name']}"
        )

        output.append(
            f"    Tactic     : "
            f"{technique['tactic']}"
        )

        output.append(
            f"    Confidence : "
            f"{technique['confidence']}"
        )

        output.append(
            "    Evidence:"
        )

        output.extend(
            technique["evidence"]
        )

        output.append(
            "    Limitation:"
        )

        output.append(
            f"      {technique['limitation']}"
        )

        output.append("")


output.append(
    "========== MAPPING COMPLETE =========="
)

Path(OUTPUT_FILE).write_text(
    "\n".join(output) + "\n",
    encoding="utf-8"
)


# ============================================================
# COMPLETE
# ============================================================

print("========== MAPPING COMPLETE ==========")
print()
print(f"Output: {OUTPUT_FILE}")
print()
