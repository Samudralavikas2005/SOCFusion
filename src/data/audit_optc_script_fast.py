import os
import pandas as pd
import gzip
import hashlib
from collections import defaultdict
import re

data_dir = "/home/vikas/SOCFusion/data/raw/optc/23Sep19-red"
out_dir = "/home/vikas/SOCFusion/data/analysis/optc_selective"
os.makedirs(out_dir, exist_ok=True)

print("Starting Step 2, 3, 4: Data Parsing (Vectorized)")
chunksize = 2000000
csv_file = "/home/vikas/SOCFusion/data/processed/optc_parsed_enriched.csv"

total_events = 0
unique_hosts = set()
events_per_host = defaultdict(int)
event_types = defaultdict(int)
process_events = 0
valid_pid_ppid = 0
duplicate_event_ids = 0
duplicate_object_ids = 0

seen_events = set()
seen_objects = set()
parent_child = set()

labels_info = []

obj_id_pattern = re.compile(r'"objectID":"([^"]+)"')

# Process in chunks using vectorized operations
for chunk in pd.read_csv(csv_file, chunksize=chunksize, dtype=str):
    total_events += len(chunk)
    print(f"Processed {total_events} events...")
    
    # Fill NA for required strings
    chunk['host'] = chunk['host'].fillna('')
    chunk['event_type'] = chunk['event_type'].fillna('')
    chunk['log_type'] = chunk['log_type'].fillna('')
    chunk['process_id'] = chunk['process_id'].fillna('')
    chunk['parent_process_id'] = chunk['parent_process_id'].fillna('')
    chunk['event_id'] = chunk['event_id'].fillna('')
    chunk['technique_id'] = chunk['technique_id'].fillna('')
    chunk['raw_event'] = chunk['raw_event'].fillna('')
    
    # 1. Hosts
    host_counts = chunk[chunk['host'] != '']['host'].value_counts()
    for h, c in host_counts.items():
        unique_hosts.add(h)
        events_per_host[h] += c
        
    # 2. Event Types
    type_counts = chunk[chunk['event_type'] != '']['event_type'].value_counts()
    for t, c in type_counts.items():
        event_types[t] += c
        
    # 3. Processes
    proc_mask = chunk['log_type'].str.contains('PROCESS', na=False) | chunk['event_type'].str.contains('PROCESS', na=False)
    proc_chunk = chunk[proc_mask]
    process_events += len(proc_chunk)
    
    valid_proc_mask = (proc_chunk['process_id'] != '') & (proc_chunk['parent_process_id'] != '')
    valid_pid_ppid += valid_proc_mask.sum()
    
    # Edges
    for _, row in proc_chunk[valid_proc_mask][['host', 'parent_process_id', 'process_id']].drop_duplicates().iterrows():
        parent_child.add((row['host'], row['parent_process_id'], row['process_id']))
        
    # 4. Duplicate Event IDs
    ev_ids = chunk[chunk['event_id'] != '']['event_id']
    unique_ev_ids = set(ev_ids)
    duplicate_event_ids += (len(ev_ids) - len(unique_ev_ids))
    intersection = seen_events.intersection(unique_ev_ids)
    duplicate_event_ids += len(intersection)
    seen_events.update(unique_ev_ids)
    
    # 5. Object IDs
    raw_events = chunk[chunk['raw_event'] != '']['raw_event']
    extracted_objs = raw_events.str.extract(obj_id_pattern, expand=False).dropna()
    unique_objs = set(extracted_objs)
    duplicate_object_ids += (len(extracted_objs) - len(unique_objs))
    intersection = seen_objects.intersection(unique_objs)
    duplicate_object_ids += len(intersection)
    seen_objects.update(unique_objs)
    
    # 6. Labels
    label_mask = chunk['technique_id'].str.strip() != ''
    if label_mask.sum() > 0:
        labels_chunk = chunk[label_mask][['technique_id', 'host', 'timestamp', 'process_name', 'command_line', 'event_id']].copy()
        labels_chunk = labels_chunk.fillna("")
        for _, row in labels_chunk.iterrows():
            labels_info.append({
                'technique_id': row['technique_id'],
                'host': row['host'],
                'timestamp': row['timestamp'],
                'process_name': row['process_name'],
                'command_line': row['command_line'],
                'source_event': row['event_id']
            })

labels_df = pd.DataFrame(labels_info)
labels_df.to_csv(os.path.join(out_dir, "label_audit_raw.csv"), index=False)

stats_md = f"""# Dataset Stats

- total events: {total_events}
- unique hosts: {len(unique_hosts)}
- events per host: {dict(events_per_host)}
- event types: {dict(event_types)}
- process events: {process_events}
- PID/PPID coverage: {valid_pid_ppid} / {process_events}
- duplicate event IDs: {duplicate_event_ids}
- duplicate objectIDs: {duplicate_object_ids}
- unique parent-child edges: {len(parent_child)}
"""
with open(os.path.join(out_dir, "stats_temp.md"), "w") as f:
    f.write(stats_md)
print("Finished Vectorized!")
