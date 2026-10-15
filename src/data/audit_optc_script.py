import os
import pandas as pd
import gzip
import hashlib
from collections import defaultdict
import re

data_dir = "/home/vikas/SOCFusion/data/raw/optc/23Sep19-red"
out_dir = "/home/vikas/SOCFusion/data/analysis/optc_selective"
os.makedirs(out_dir, exist_ok=True)

print("Starting Step 1: Integrity Check")
md_content = "# OpTC Download Integrity Report\n\n"
md_content += "| File | Compressed Size (MB) | MD5 (first 10MB) | GZIP | Status |\n"
md_content += "|---|---|---|---|---|\n"

for root, dirs, files in os.walk(data_dir):
    for file in files:
        if file.endswith('.json.gz'):
            filepath = os.path.join(root, file)
            size_mb = os.path.getsize(filepath) / (1024 * 1024)
            is_truncated = any(f.startswith(file) and f.endswith('.part') for f in files)
            
            md5_hash = hashlib.md5()
            try:
                with open(filepath, 'rb') as f:
                    md5_hash.update(f.read(10 * 1024 * 1024))
                md5_str = md5_hash.hexdigest()
            except:
                md5_str = "Error"

            try:
                with gzip.open(filepath, 'rb') as f:
                    f.read(1)
                gzip_ok = "Valid"
            except:
                gzip_ok = "Invalid"
            
            status = "Truncated/Incomplete" if is_truncated else "Complete"
            md_content += f"| {file} | {size_mb:.2f} | {md5_str} | {gzip_ok} | {status} |\n"

with open(os.path.join(out_dir, "download_integrity.md"), "w") as f:
    f.write(md_content)

print("Starting Step 2, 3, 4: Data Parsing")
chunksize = 1000000
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

# Process in chunks
for chunk in pd.read_csv(csv_file, chunksize=chunksize, dtype=str):
    total_events += len(chunk)
    print(f"Processed {total_events} events...")
    
    for _, row in chunk.iterrows():
        host = str(row['host'])
        if host and host != 'nan':
            unique_hosts.add(host)
            events_per_host[host] += 1
            
        ev_type = str(row['event_type'])
        if ev_type and ev_type != 'nan':
            event_types[ev_type] += 1
            
        is_process = False
        log_type = str(row['log_type'])
        if "PROCESS" in log_type or "PROCESS" in ev_type:
            process_events += 1
            is_process = True
            pid = str(row['process_id'])
            ppid = str(row['parent_process_id'])
            if pid != 'nan' and ppid != 'nan':
                valid_pid_ppid += 1
                parent_child.add((host, ppid, pid))
                
        ev_id = str(row['event_id'])
        if ev_id != 'nan':
            if ev_id in seen_events:
                duplicate_event_ids += 1
            else:
                seen_events.add(ev_id)
            
        raw = str(row['raw_event'])
        if raw != 'nan':
            match = obj_id_pattern.search(raw)
            if match:
                obj_id = match.group(1)
                if obj_id in seen_objects:
                    duplicate_object_ids += 1
                else:
                    seen_objects.add(obj_id)
                
        tech = str(row['technique_id'])
        if tech and tech != 'nan' and tech.strip():
            labels_info.append({
                'technique_id': tech,
                'host': host,
                'timestamp': str(row['timestamp']),
                'process_name': str(row['process_name']),
                'command_line': str(row['command_line']),
                'source_event': ev_id
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
print("Finished!")
