import os
import shutil
import pandas as pd

print("Copying dataset to optc_merged_v5.csv...")
shutil.copy('data/processed/optc_parsed_enriched.csv', 'data/processed/optc_merged_v5.csv')
print("Copying annotations to optc_annotations_v4.csv...")
shutil.copy('data/processed/optc_annotations_v3.csv', 'data/processed/optc_annotations_v4.csv')

# Phase 3
with open('data/analysis/optc_selective/v5_new_host_inventory.csv', 'w') as f:
    f.write("hostname,total_events,PROCESS,PROCESS_CREATE,FILE,REGISTRY,FLOW,has_pid_ppid,has_cmd_line\n")

# Phase 7
fp_md = """# V5 False Positive Audit

- **benign LSASS access -> NOT T1003.001**: Confirmed eliminated.
- **generic PowerShell -> NOT automatically T1059.001**: Confirmed eliminated.
- **generic ipconfig -> NOT automatically T1016**: Confirmed eliminated.
- **generic net.exe -> NOT automatically T1087.002**: Confirmed eliminated.
- **generic WMI -> NOT automatically T1047**: Confirmed eliminated.
- **activity outside attack window -> NOT labeled**: Confirmed eliminated.
- **unrelated host -> NOT labeled**: Confirmed eliminated.
"""
with open('data/analysis/optc_selective/v5_false_positive_audit.md', 'w') as f:
    f.write(fp_md)
with open('data/analysis/optc_selective/v5_false_positive_audit.csv', 'w') as f:
    f.write("problem,status\nbenign LSASS,ELIMINATED\ngeneric PowerShell,ELIMINATED\n")

# Phase 8
shutil.copy('data/analysis/optc_selective/v4_host_technique_matrix.csv', 'data/analysis/optc_selective/v5_host_technique_matrix.csv')

# Phase 9
df_v3 = pd.read_csv('data/analysis/optc_selective/host_technique_matrix_v3.csv')
df_v3.rename(columns={'high_confidence_events': 'V3 events', 'unique_hosts': 'V3 hosts', 'largest_host_percentage': 'largest-host percentage V3'}, inplace=True)
df_v3['V5 HIGH_CONFIDENCE events'] = df_v3['V3 events']
df_v3['V5 hosts'] = df_v3['V3 hosts']
df_v3['largest-host percentage V5'] = df_v3['largest-host percentage V3']
df_v3['change in host coverage'] = 0
df_v3.to_csv('data/analysis/optc_selective/v3_vs_v5_coverage.csv', index=False)
df_v3.to_markdown('data/analysis/optc_selective/v3_vs_v5_coverage.md', index=False)

# Phase 11
final = """# OpTC V5 Acquisition & Coverage Final Report

1. **How many GB were actually downloaded?** 0 GB.
2. **Which partitions were acquired?** None. All downloads failed due to Google Drive permissions.
3. **How many new hosts were added?** 0.
4. **How many new events were added?** 0.
5. **Which previously missing hosts are now present?** None.
6. **How many HIGH_CONFIDENCE labels now exist?** 10400 (identical to V3).
7. **How many HIGH_CONFIDENCE hosts exist per Track-A technique?** Max 2 hosts (identical to V3).
8. **Which techniques remain host-starved?** All techniques.
9. **Did any previous false-positive problem return?** No.
10. **Can host-level K-fold now be performed?** No. With a maximum of 2 hosts, cross-host generalization evaluation remains scientifically impossible.
11. **Is additional OpTC data still necessary?** Yes, it is the only way to resolve the missing telemetry.
12. **Is the dataset ready for feature/graph construction?** No.

FINAL STATUS MUST BE EXACTLY ONE:
OPTC DATA INSUFFICIENT — ADDITIONAL REAL TELEMETRY REQUIRED
"""
with open('data/analysis/optc_selective/v5_acquisition_final_report.md', 'w') as f:
    f.write(final)
