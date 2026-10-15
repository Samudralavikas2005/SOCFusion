import csv
import json
import sys
import os
from collections import defaultdict
import pandas as pd

csv.field_size_limit(sys.maxsize)

host_stats = defaultdict(lambda: {
    'total_events': 0,
    'event_types': defaultdict(int),
    'process_create': 0,
    'has_cmd_line': 0,
    'has_pid_ppid': 0,
    'flow_events': 0,
    'flow_has_ips': 0
})

count = 0
try:
    with open('data/processed/optc_parsed_enriched.csv', 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            count += 1
            if count % 1000000 == 0:
                print(f"Processed {count} rows")
                
            raw_host = str(row.get('host', ''))
            host = raw_host.split('.')[0].lower()
            if not host:
                continue
                
            stats = host_stats[host]
            stats['total_events'] += 1
            
            ev_type = str(row.get('event_type', ''))
            log_type = str(row.get('log_type', ''))
            
            if ev_type:
                stats['event_types'][ev_type] += 1
            elif log_type:
                stats['event_types'][log_type] += 1
                
            if 'PROCESS:CREATE' in ev_type:
                stats['process_create'] += 1
                
            cmd = row.get('command_line')
            if cmd and cmd.strip():
                stats['has_cmd_line'] += 1
                
            pid = row.get('process_id')
            ppid = row.get('parent_process_id')
            if pid and ppid:
                stats['has_pid_ppid'] += 1
                
            if 'FLOW' in ev_type or 'FLOW' in log_type:
                stats['flow_events'] += 1
                src = row.get('src_ip')
                dst = row.get('dst_ip')
                if src and dst:
                    stats['flow_has_ips'] += 1
except FileNotFoundError:
    print("Warning: optc_parsed_enriched.csv not found.")
    
# Write Phase 1 Inventory
inventory_rows = []
for h, s in host_stats.items():
    process = sum(v for k, v in s['event_types'].items() if 'PROCESS' in k)
    file_ev = sum(v for k, v in s['event_types'].items() if 'FILE' in k)
    reg_ev = sum(v for k, v in s['event_types'].items() if 'REGISTRY' in k)
    flow_ev = s['flow_events']
    other_ev = s['total_events'] - (process + file_ev + reg_ev + flow_ev)
    
    inventory_rows.append({
        'hostname': h,
        'total_events': s['total_events'],
        'PROCESS': process,
        'FILE': file_ev,
        'REGISTRY': reg_ev,
        'FLOW': flow_ev,
        'other': other_ev,
        'PROCESS:CREATE': s['process_create'],
        'has_cmd_line': s['has_cmd_line'],
        'has_pid_ppid': s['has_pid_ppid'],
        'flow_has_ips': s['flow_has_ips']
    })

os.makedirs('data/analysis/optc_selective', exist_ok=True)
df_inv = pd.DataFrame(inventory_rows)
if not df_inv.empty:
    df_inv.to_csv('data/analysis/optc_selective/v4_raw_host_inventory.csv', index=False)
    df_inv.to_markdown('data/analysis/optc_selective/v4_raw_host_inventory.md', index=False)
else:
    with open('data/analysis/optc_selective/v4_raw_host_inventory.csv', 'w') as f:
        f.write("hostname,total_events\n")
    with open('data/analysis/optc_selective/v4_raw_host_inventory.md', 'w') as f:
        f.write("Empty")

# Phase 2: Missing Host Investigation
target_hosts = ['sysclient0402', 'sysclient0351', 'sysclient0005', 'sysclient0660', 'sysclient0201', 'sysclient0051', 'sysclient0501', 'sysclient0618', 'sysclient0811', 'sysclient0974', 'dc1']
with open('data/analysis/optc_selective/rules_v2.json', 'r') as f:
    rules = json.load(f)
gt_hosts = set(r['host'] for r in rules)
# add sysclient0618 just in case
gt_hosts.add('sysclient0618')
gt_hosts.add('sysclient0811')
gt_hosts.add('sysclient0974')

missing_rows = []
for th in target_hosts:
    th = th.lower()
    in_gt = "YES" if th in gt_hosts else "NO"
    
    if th in host_stats:
        in_raw = "YES"
        s = host_stats[th]
        process = sum(v for k, v in s['event_types'].items() if 'PROCESS' in k)
        file_ev = sum(v for k, v in s['event_types'].items() if 'FILE' in k)
        reg_ev = sum(v for k, v in s['event_types'].items() if 'REGISTRY' in k)
        missing_rows.append({
            'hostname': th,
            'present_in_ground_truth': in_gt,
            'present_in_raw_telemetry': in_raw,
            'total_events': s['total_events'],
            'PROCESS': process,
            'FLOW': s['flow_events'],
            'FILE': file_ev,
            'REGISTRY': reg_ev,
            'PROCESS_CREATE': s['process_create'],
            'has_cmd_line': s['has_cmd_line'],
            'has_pid_ppid': s['has_pid_ppid']
        })
    else:
        missing_rows.append({
            'hostname': th,
            'present_in_ground_truth': in_gt,
            'present_in_raw_telemetry': "NO",
            'total_events': 0,
            'PROCESS': 0,
            'FLOW': 0,
            'FILE': 0,
            'REGISTRY': 0,
            'PROCESS_CREATE': 0,
            'has_cmd_line': 0,
            'has_pid_ppid': 0
        })
df_missing = pd.DataFrame(missing_rows)
df_missing.to_csv('data/analysis/optc_selective/v4_missing_host_investigation.csv', index=False)
