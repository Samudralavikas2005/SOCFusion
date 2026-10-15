import pandas as pd
import json

df_inv = pd.read_csv('data/analysis/optc_selective/v4_raw_host_inventory.csv')
target_hosts = ['sysclient0402', 'sysclient0351', 'sysclient0005', 'sysclient0660', 'sysclient0201', 'sysclient0051', 'sysclient0501', 'sysclient0618', 'sysclient0811', 'sysclient0974', 'dc1']
with open('data/analysis/optc_selective/rules_v2.json', 'r') as f: rules = json.load(f)
gt_hosts = set(r['host'] for r in rules)
gt_hosts.update(['sysclient0618', 'sysclient0811', 'sysclient0974'])

missing_rows = []
for th in target_hosts:
    th = th.lower()
    in_gt = 'YES' if th in gt_hosts else 'NO'
    row = df_inv[df_inv['hostname'] == th]
    if not row.empty:
        r = row.iloc[0]
        missing_rows.append({
            'hostname': th, 'present_in_ground_truth': in_gt, 'present_in_raw_telemetry': 'YES',
            'total_events': r['total_events'], 'PROCESS': r['PROCESS'], 'FLOW': r['FLOW'],
            'FILE': r['FILE'], 'REGISTRY': r['REGISTRY'], 'PROCESS_CREATE': r['PROCESS:CREATE'],
            'has_cmd_line': r['has_cmd_line'], 'has_pid_ppid': r['has_pid_ppid']
        })
    else:
        missing_rows.append({
            'hostname': th, 'present_in_ground_truth': in_gt, 'present_in_raw_telemetry': 'NO',
            'total_events': 0, 'PROCESS': 0, 'FLOW': 0, 'FILE': 0, 'REGISTRY': 0,
            'PROCESS_CREATE': 0, 'has_cmd_line': 0, 'has_pid_ppid': 0
        })
pd.DataFrame(missing_rows).to_csv('data/analysis/optc_selective/v4_missing_host_investigation.csv', index=False)
