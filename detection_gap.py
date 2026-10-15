import csv
from pathlib import Path
from collections import defaultdict


# ============================================================
# CONFIGURATION
# ============================================================

MITRE_FILE = "data/mitre_mapping.txt"
OUTPUT_FILE = "data/detection_gap_report.txt"
CSV_OUTPUT = "data/detection_gaps.csv"

# Current reconstructed techniques
TECHNIQUES = {
    "T1112": {
        "name": "Modify Registry",
        "tactic": "Persistence / Defense Evasion",
    },
    "T1055": {
        "name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
    },
}


# ============================================================
# LOAD MITRE MAPPING
# ============================================================

def load_mitre_mapping():

    mappings = []

    current_id = None
    current_name = None
    current_confidence = None

    with open(MITRE_FILE, encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            # Example:
            # [1] T1112 - Modify Registry
            if line.startswith("[") and "] T" in line:

                parts = line.split("] ", 1)

                if len(parts) != 2:
                    continue

                technique_part = parts[1]

                technique_id, technique_name = technique_part.split(
                    " - ",
                    1
                )

                current_id = technique_id.strip()
                current_name = technique_name.strip()

            elif line.startswith("Confidence"):

                current_confidence = line.split(":", 1)[1].strip()

                if current_id:

                    mappings.append({
                        "technique": current_id,
                        "name": current_name,
                        "confidence": current_confidence,
                    })

                    current_id = None
                    current_name = None
                    current_confidence = None

    return mappings


# ============================================================
# BUILD DETECTION-GAP ANALYSIS
# ============================================================

mitre_mappings = load_mitre_mapping()


print()
print("========== SOCFUSION DETECTION GAP ANALYZER ==========")
print()

print(
    f"MITRE techniques observed : {len(mitre_mappings)}"
)

print()


# ============================================================
# IMPORTANT:
#
# We do NOT claim that an external SIEM detected these events.
#
# The current graph contains attack evidence and MITRE mapping,
# but no verified Wazuh/Splunk alert stream for this exact graph.
#
# Therefore:
#
#   evidence_present = TRUE
#   detection_verified = UNKNOWN
#
# This prevents fabricated detection coverage.
# ============================================================

results = []


for mapping in mitre_mappings:

    technique = mapping["technique"]

    name = mapping["name"]

    confidence = mapping["confidence"]

    if technique not in TECHNIQUES:
        tactic = "Unknown"
    else:
        tactic = TECHNIQUES[technique]["tactic"]


    results.append({
        "technique": technique,
        "name": name,
        "tactic": tactic,
        "mapping_confidence": confidence,
        "attack_evidence": "PRESENT",
        "detection_verified": "UNKNOWN",
        "gap_status": "UNVERIFIED",
        "miss_rate": "",
    })


# ============================================================
# PRINT RESULTS
# ============================================================

print("========== DETECTION COVERAGE ==========")
print()

for result in results:

    print(
        f"{result['technique']} - "
        f"{result['name']}"
    )

    print(
        f"  Tactic             : "
        f"{result['tactic']}"
    )

    print(
        f"  Mapping confidence : "
        f"{result['mapping_confidence']}"
    )

    print(
        f"  Attack evidence    : "
        f"{result['attack_evidence']}"
    )

    print(
        f"  Detection verified : "
        f"{result['detection_verified']}"
    )

    print(
        f"  Gap status         : "
        f"{result['gap_status']}"
    )

    print()


# ============================================================
# DETECTION GAP SUMMARY
# ============================================================

print("========== GAP SUMMARY ==========")
print()

if not results:

    print("No mapped techniques available.")

else:

    print(
        "Detection coverage cannot yet be classified as "
        "DETECTED or MISSED."
    )

    print()

    print(
        "Reason:"
    )

    print(
        "The current Day-2 graph contains attack evidence "
        "and MITRE mappings, but no verified SIEM alert "
        "stream corresponding to these exact events."
    )

    print()

    print(
        "Therefore SOCFusion marks these techniques as "
        "UNVERIFIED rather than falsely reporting a detection gap."
    )


# ============================================================
# SAVE TEXT REPORT
# ============================================================

output = []

output.append(
    "========== SOCFUSION DETECTION GAP ANALYZER =========="
)

output.append("")

output.append(
    f"MITRE techniques observed : {len(results)}"
)

output.append("")

output.append(
    "========== DETECTION COVERAGE =========="
)

output.append("")

for result in results:

    output.append(
        f"{result['technique']} - {result['name']}"
    )

    output.append(
        f"  Tactic             : {result['tactic']}"
    )

    output.append(
        f"  Mapping confidence : {result['mapping_confidence']}"
    )

    output.append(
        f"  Attack evidence    : {result['attack_evidence']}"
    )

    output.append(
        f"  Detection verified : {result['detection_verified']}"
    )

    output.append(
        f"  Gap status         : {result['gap_status']}"
    )

    output.append("")


output.append(
    "========== GAP SUMMARY =========="
)

output.append("")

output.append(
    "Detection coverage cannot yet be classified as "
    "DETECTED or MISSED."
)

output.append("")

output.append(
    "The current graph contains attack evidence and MITRE "
    "mappings, but no verified SIEM alert stream corresponding "
    "to these exact events."
)

output.append("")

output.append(
    "SOCFusion therefore marks the techniques as UNVERIFIED "
    "rather than fabricating detection coverage."
)

output.append("")

output.append(
    "========== ANALYSIS COMPLETE =========="
)

Path(OUTPUT_FILE).write_text(
    "\n".join(output) + "\n",
    encoding="utf-8"
)


# ============================================================
# SAVE CSV
# ============================================================

with open(
    CSV_OUTPUT,
    "w",
    newline="",
    encoding="utf-8"
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "technique",
            "name",
            "tactic",
            "mapping_confidence",
            "attack_evidence",
            "detection_verified",
            "gap_status",
            "miss_rate",
        ]
    )

    writer.writeheader()

    writer.writerows(results)


# ============================================================
# COMPLETE
# ============================================================

print()
print("========== ANALYSIS COMPLETE ==========")
print()
print(f"Text report : {OUTPUT_FILE}")
print(f"CSV report  : {CSV_OUTPUT}")
print()
