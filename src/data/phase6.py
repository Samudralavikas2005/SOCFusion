import pandas as pd

# Phase 6
add_cands = []
add_cands.append({
    'file': 'ecar/evaluation/23Sep19-red/AIA-501-525.ecar-last.json.gz (Google Drive)',
    'estimated_size': '~1.5 GB',
    'hosts': 'sysclient0501',
    'expected_techniques': 'T1059.001 (PowerShell), T1047 (WMI)',
    'telemetry_types': 'PROCESS, FILE, FLOW, REGISTRY',
    'ground_truth_available': 'YES',
    'reason_to_download': 'Contains sysclient0501 which has documented red-team activity (WMI pivot, PowerShell).',
    'priority': 'HIGH'
})
add_cands.append({
    'file': 'ecar/evaluation/23Sep19-red/AIA-51-75.ecar-last.json.gz (Google Drive)',
    'estimated_size': '~1.5 GB',
    'hosts': 'sysclient0051',
    'expected_techniques': 'T1059.001 (PowerShell), T1047 (WMI)',
    'telemetry_types': 'PROCESS, FILE, FLOW, REGISTRY',
    'ground_truth_available': 'YES',
    'reason_to_download': 'Contains sysclient0051 which has documented red-team activity.',
    'priority': 'HIGH'
})
add_cands.append({
    'file': 'ecar/evaluation/23Sep19-red/AIA-801-825.ecar-last.json.gz (Google Drive)',
    'estimated_size': '~1.5 GB',
    'hosts': 'sysclient0811',
    'expected_techniques': 'T1059.001 (PowerShell), T1047 (WMI)',
    'telemetry_types': 'PROCESS, FILE, FLOW, REGISTRY',
    'ground_truth_available': 'YES',
    'reason_to_download': 'Contains sysclient0811 which has documented red-team activity.',
    'priority': 'HIGH'
})
add_cands.append({
    'file': 'ecar/evaluation/23Sep19-red/AIA-951-975.ecar-last.json.gz (Google Drive)',
    'estimated_size': '~1.5 GB',
    'hosts': 'sysclient0974',
    'expected_techniques': 'T1059.001 (PowerShell), T1047 (WMI)',
    'telemetry_types': 'PROCESS, FILE, FLOW, REGISTRY',
    'ground_truth_available': 'YES',
    'reason_to_download': 'Contains sysclient0974 which has documented red-team activity.',
    'priority': 'HIGH'
})
add_cands.append({
    'file': 'ecar/evaluation/23Sep19-red/AIA-server.ecar-last.json.gz (Google Drive) / domain controllers',
    'estimated_size': '~2.0 GB',
    'hosts': 'DC1',
    'expected_techniques': 'T1059.001, T1047, etc.',
    'telemetry_types': 'PROCESS, FILE, FLOW, REGISTRY',
    'ground_truth_available': 'YES',
    'reason_to_download': 'Contains DC1 which was a primary target for WMI lateral movement.',
    'priority': 'HIGH'
})

pd.DataFrame(add_cands).to_csv('data/analysis/optc_selective/v4_additional_data_candidates.csv', index=False)

final_report = """# OpTC V4 Data Coverage Investigation

1. **Are the missing hosts actually absent from the raw telemetry?** Yes. Hosts like dc1, sysclient0501, sysclient0051, sysclient0811, and sysclient0974 do not appear in the currently downloaded raw telemetry files at all. The data partitions corresponding to their host groups (e.g., AIA-501-525, AIA-51-75) were never downloaded from the Google Drive repository.
2. **Which documented hosts have usable PROCESS telemetry?** sysclient0201, sysclient0660.
3. **Which documented hosts have only FLOW telemetry?** The remaining hosts that were downloaded (sysclient0402, sysclient0351, sysclient0005) only have FLOW or FILE telemetry during the documented attacks, lacking the necessary PROCESS telemetry to verify the attack commands.
4. **Which attack actions have direct process evidence?** The actions on sysclient0201 (e.g. Mimikatz, PowerShell) and sysclient0660.
5. **Which attack actions are flow-only?** Ping sweeps on sysclient0402, WMI pivots from sysclient0402 to sysclient0660, and share mounts on sysclient0005.
6. **Can flow-only actions be labeled scientifically without guessing?** No. A FLOW event alone lacks the process context to determine if it was initiated by a malicious script or benign background activity.
7. **How many independent hosts exist for each Track-A technique?** At most 2 (sysclient0201 and sysclient0660).
8. **Which techniques remain host-starved?** All techniques are host-starved (max 2 hosts), completely inhibiting scientific cross-host evaluation.
9. **Does additional OpTC data exist that can realistically solve the host-starvation problem?** Yes. The missing hosts (sysclient0501, sysclient0051, sysclient0811, sysclient0974, and DC1) all have documented red-team ground truth. Their raw telemetry resides in un-downloaded eCAR partitions on the OpTC Google Drive. 
10. **What exact files should be downloaded next, if any?** `AIA-501-525`, `AIA-51-75`, `AIA-801-825`, `AIA-951-975`, and any server partition containing `DC1`.
11. **How many GB would those files require?** Approximately 6-8 GB compressed (based on ~1.5 GB per 25-host group).
12. **What is the minimum additional data actually necessary?** At least 2-3 of the missing host partitions (e.g., `AIA-501-525` and `AIA-51-75`) must be downloaded and parsed to provide enough independent host coverage for the host-starved techniques.
13. **Is the current dataset scientifically ready for supervised GAT training?** No. The lack of host diversity prevents evaluating whether the model generalizes across environments or merely overfits to sysclient0201 and sysclient0660.

FINAL STATUS MUST BE EXACTLY ONE OF:
OPTC DATA INSUFFICIENT — ADDITIONAL REAL TELEMETRY REQUIRED
"""
with open('data/analysis/optc_selective/v4_coverage_final_report.md', 'w') as f:
    f.write(final_report)
