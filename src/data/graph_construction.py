import csv
import sys
import os
import hashlib
import json
import pickle
import math

def get_hash(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def main():
    csv.field_size_limit(sys.maxsize)
    V4_CSV = "data/processed/normalized_events_v4.csv"
    FEATURES_CSV = "data/processed/features_v1/features.csv"
    
    OUTPUT_DIR = "data/processed/graphs_v1"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUTPUT_DIR, "node_mappings"), exist_ok=True)
    
    # 1. Read Hosts and define Split
    print("Partitioning hosts...")
    unique_hosts = set()
    with open(V4_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host = row.get('host', '').strip()
            if not host:
                host = 'UNKNOWN_HOST'
            unique_hosts.add(host)
                
    sorted_hosts = sorted(list(unique_hosts))
    
    n_hosts = len(sorted_hosts)
    train_end = int(n_hosts * 0.70)
    val_end = int(n_hosts * 0.85)
    
    train_hosts = set(sorted_hosts[:train_end])
    val_hosts = set(sorted_hosts[train_end:val_end])
    test_hosts = set(sorted_hosts[val_end:])
    
    host_to_partition = {}
    for h in train_hosts: host_to_partition[h] = 'train'
    for h in val_hosts: host_to_partition[h] = 'val'
    for h in test_hosts: host_to_partition[h] = 'test'
    
    print(f"Train hosts: {len(train_hosts)}, Val hosts: {len(val_hosts)}, Test hosts: {len(test_hosts)}")
    
    # Label mapping
    techniques = set()
    with open(FEATURES_CSV, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            techniques.add(row['technique_id'])
    sorted_techs = sorted(list(techniques))
    label_mapping = {tech: idx for idx, tech in enumerate(sorted_techs)}
    with open(os.path.join(OUTPUT_DIR, "label_mapping.json"), 'w') as f:
        json.dump(label_mapping, f, indent=2)

    MODEL_FEATURE_COLUMNS = [
        "hour_sin", "hour_cos", "day_of_week_sin", "day_of_week_cos",
        "log_type_idx", "event_code_idx", "source_idx", "process_name_idx",
        "is_lolbin", "msg_length", "ps_token_count", "cmd_length", 
        "cmd_entropy", "ps_b64_indicator", "has_process_id", "has_user", "has_command_line"
    ]

    # Data structures for splits
    splits = {
        'train': {'events': [], 'features': [], 'labels': [], 'hosts': {}, 'users': {}, 'processes': {}, 'run_edges': ([],[]), 'exec_edges': ([],[]), 'inv_edges': ([],[]), 'spawn_edges': ([],[]), 'prec_edges': ([],[])},
        'val': {'events': [], 'features': [], 'labels': [], 'hosts': {}, 'users': {}, 'processes': {}, 'run_edges': ([],[]), 'exec_edges': ([],[]), 'inv_edges': ([],[]), 'spawn_edges': ([],[]), 'prec_edges': ([],[])},
        'test': {'events': [], 'features': [], 'labels': [], 'hosts': {}, 'users': {}, 'processes': {}, 'run_edges': ([],[]), 'exec_edges': ([],[]), 'inv_edges': ([],[]), 'spawn_edges': ([],[]), 'prec_edges': ([],[])}
    }
    
    stats = {
        'train': {'event_count': 0, 'spawned_created': 0, 'spawned_rejected': 0, 'precedes_count': 0},
        'val': {'event_count': 0, 'spawned_created': 0, 'spawned_rejected': 0, 'precedes_count': 0},
        'test': {'event_count': 0, 'spawned_created': 0, 'spawned_rejected': 0, 'precedes_count': 0}
    }
    
    # Process tracking for spawned edges (only GUID)
    guid_to_id = {'train': {}, 'val': {}, 'test': {}}
    
    # Temporal tracking per host for PRECEDES
    host_time_queues = {'train': {}, 'val': {}, 'test': {}}
    
    print("Streaming and building graphs...")
    with open(V4_CSV, 'r', encoding='utf-8') as f_v4, open(FEATURES_CSV, 'r', encoding='utf-8') as f_feat:
        reader_v4 = csv.DictReader(f_v4)
        reader_feat = csv.DictReader(f_feat)
        
        for row_v4, row_feat in zip(reader_v4, reader_feat):
            host = row_v4.get('host', '').strip()
            if not host:
                host = 'UNKNOWN_HOST'
            
            part = host_to_partition.get(host)
            if not part: continue
            
            s = splits[part]
            s_stats = stats[part]
            
            event_idx = len(s['events'])
            s['events'].append(row_feat['event_id'])
            s_stats['event_count'] += 1
            
            feat_vec = [float(row_feat[c]) for c in MODEL_FEATURE_COLUMNS]
            s['features'].append(feat_vec)
            
            s['labels'].append(label_mapping[row_feat['technique_id']])
            
            # Host edge
            if host != 'UNKNOWN_HOST':
                if host not in s['hosts']: s['hosts'][host] = len(s['hosts'])
                host_idx = s['hosts'][host]
                s['run_edges'][0].append(event_idx)
                s['run_edges'][1].append(host_idx)
                
            # User edge
            user = row_v4.get('user', '')
            if user:
                user_id = get_hash(user)
                if user_id not in s['users']: s['users'][user_id] = len(s['users'])
                user_idx = s['users'][user_id]
                s['exec_edges'][0].append(event_idx)
                s['exec_edges'][1].append(user_idx)
                
            # Process Edge
            p_guid = row_v4.get('process_guid', '')
            pid = row_v4.get('process_id', '')
            p_name = row_v4.get('process_name', '')
            
            proc_id = None
            is_guid = False
            if p_guid:
                proc_id = get_hash(p_guid)
                is_guid = True
                guid_to_id[part][p_guid] = proc_id
            elif pid:
                # 1-hour window block based on timestamp
                ts_str = row_v4.get('timestamp', '')
                try:
                    from dateutil import parser as dt_parser
                    ts = dt_parser.parse(ts_str).timestamp()
                except Exception:
                    ts = 0
                time_block = int(ts // 3600)
                proc_id = get_hash(f"{host}_{p_name}_{pid}_{time_block}")
                
            if proc_id:
                if proc_id not in s['processes']: s['processes'][proc_id] = len(s['processes'])
                proc_idx = s['processes'][proc_id]
                s['inv_edges'][0].append(event_idx)
                s['inv_edges'][1].append(proc_idx)
                
                # Parent-child
                parent_guid = row_v4.get('parent_process_guid', '')
                if parent_guid and parent_guid in guid_to_id[part] and is_guid:
                    parent_proc_id = guid_to_id[part][parent_guid]
                    if parent_proc_id in s['processes']:
                        parent_idx = s['processes'][parent_proc_id]
                        s['spawn_edges'][0].append(parent_idx)
                        s['spawn_edges'][1].append(proc_idx)
                        s_stats['spawned_created'] += 1
                elif row_v4.get('parent_process_id'):
                    # Rejected because no guid match
                    s_stats['spawned_rejected'] += 1
                    
            # Temporal PRECEDES edges
            ts_str = row_v4.get('timestamp', '')
            try:
                ts = dt_parser.parse(ts_str).timestamp()
            except Exception:
                ts = 0
            if host not in host_time_queues[part]:
                host_time_queues[part][host] = []
            
            queue = host_time_queues[part][host]
            # prune queue to last 1 hour
            while queue and ts - queue[0][0] > 3600:
                queue.pop(0)
                
            # Connect up to last 3
            k = 3
            for prev_ts, prev_event_idx in reversed(queue[-k:]):
                s['prec_edges'][0].append(prev_event_idx)
                s['prec_edges'][1].append(event_idx)
                s_stats['precedes_count'] += 1
                
            queue.append((ts, event_idx))
            
    print("Writing pt files...")
    for part in ['train', 'val', 'test']:
        s = splits[part]
        graph_obj = {
            "nodes": {
                "Event": {"x": s['features'], "y": s['labels'], "num_nodes": len(s['events'])},
                "Host": {"num_nodes": len(s['hosts'])},
                "User": {"num_nodes": len(s['users'])},
                "Process": {"num_nodes": len(s['processes'])}
            },
            "edges": {
                ("Event", "RUNS_ON", "Host"): {"edge_index": s['run_edges']},
                ("Event", "EXECUTED_BY", "User"): {"edge_index": s['exec_edges']},
                ("Event", "INVOLVES", "Process"): {"edge_index": s['inv_edges']},
                ("Process", "SPAWNED", "Process"): {"edge_index": s['spawn_edges']},
                ("Event", "PRECEDES", "Event"): {"edge_index": s['prec_edges']}
            }
        }
        with open(os.path.join(OUTPUT_DIR, f"{part}_data.pt"), 'wb') as f:
            pickle.dump(graph_obj, f)
            
        with open(os.path.join(OUTPUT_DIR, "node_mappings", f"{part}_host_map.json"), 'w') as f:
            json.dump(s['hosts'], f)
            
    with open(os.path.join(OUTPUT_DIR, "graph_statistics.json"), 'w') as f:
        json.dump(stats, f, indent=2)
        
    print("Done graph construction!")

if __name__ == "__main__":
    main()
