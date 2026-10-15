import csv
import sys
import os
from collections import defaultdict, Counter
import math
from dateutil import parser as dt_parser

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT_FILE = "data/processed/normalized_events_v4.csv"
    OUTPUT_DIR = "data/analysis/graph_design_review"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    host_events = defaultdict(list)
    process_identifiers = set()
    total_events = 0
    
    print("Reading events for graph design review...")
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            total_events += 1
            host = row.get('host', '')
            ts_str = row.get('timestamp', '')
            try:
                ts = dt_parser.parse(ts_str).timestamp()
            except Exception:
                ts = 0
                
            host_events[host].append(ts)
            
            p_guid = row.get('process_guid', '')
            pid = row.get('process_id', '')
            p_name = row.get('process_name', '')
            if p_guid:
                process_identifiers.add(f"guid:{p_guid}")
            elif pid:
                process_identifiers.add(f"pid:{pid}:{host}:{p_name}")

    host_counts = []
    events_per_host_per_hour = []
    
    all_pairs_edges = 0
    k1_edges = 0
    k3_edges = 0
    k5_edges = 0
    k10_edges = 0
    
    for host, timestamps in host_events.items():
        timestamps.sort()
        count = len(timestamps)
        host_counts.append(count)
        
        left = 0
        max_in_window = 0
        for right in range(count):
            while timestamps[right] - timestamps[left] > 3600:
                left += 1
            window_size = right - left + 1
            if window_size > max_in_window:
                max_in_window = window_size
                
            window_prev_count = window_size - 1
            all_pairs_edges += window_prev_count
            k1_edges += min(1, window_prev_count)
            k3_edges += min(3, window_prev_count)
            k5_edges += min(5, window_prev_count)
            k10_edges += min(10, window_prev_count)
            
        events_per_host_per_hour.append(max_in_window)
        
    host_counts.sort()
    max_events = host_counts[-1]
    median_events = host_counts[len(host_counts)//2]
    max_per_hour = max(events_per_host_per_hour)
    
    with open(os.path.join(OUTPUT_DIR, "temporal_edge_analysis.csv"), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["metric", "value"])
        writer.writerow(["total_hosts", len(host_events)])
        writer.writerow(["max_events_per_host", max_events])
        writer.writerow(["median_events_per_host", median_events])
        writer.writerow(["max_events_within_one_hour_window", max_per_hour])
        writer.writerow(["edges_all_pairs", all_pairs_edges])
        writer.writerow(["edges_k1", k1_edges])
        writer.writerow(["edges_k3", k3_edges])
        writer.writerow(["edges_k5", k5_edges])
        writer.writerow(["edges_k10", k10_edges])
        
    with open(os.path.join(OUTPUT_DIR, "entity_node_schema.csv"), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["node_type", "features", "learned_embeddings_required"])
        writer.writerow(["Event", "17 MODEL_FEATURE_COLUMNS", "No"])
        writer.writerow(["Host", "Featureless (Empty x tensor)", "Yes (Trainable parameter)"])
        writer.writerow(["User", "Featureless (Empty x tensor)", "Yes (Trainable parameter)"])
        writer.writerow(["Process", "Featureless (Empty x tensor)", "Yes (Trainable parameter)"])

    with open(os.path.join(OUTPUT_DIR, "edge_schema_v2.csv"), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["source_type", "destination_type", "direction", "creation_rule", "max_possible_edges", "edge_attributes", "leakage_risk"])
        writer.writerow(["Event", "Host", "Directed", "Event has valid host", total_events, "None", "Low"])
        writer.writerow(["Event", "User", "Directed", "Event has valid user", total_events, "None", "Low"])
        writer.writerow(["Event", "Process", "Directed", "Event has valid process mapping", total_events, "None", "Low"])
        writer.writerow(["Process", "Process", "Directed", "Valid parent_process linkage", len(process_identifiers), "None", "Low"])
        writer.writerow(["Event", "Event", "Directed", "Same host, strictly chronological, max K previous within 1hr", k3_edges, "Temporal Delta", "Moderate"])

    with open(os.path.join(OUTPUT_DIR, "graph_scale_analysis.csv"), 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["element", "estimated_count"])
        writer.writerow(["Event_Nodes", total_events])
        writer.writerow(["Host_Nodes", len(host_events)])
        writer.writerow(["User_Nodes", 180])
        writer.writerow(["Process_Nodes", len(process_identifiers)])
        writer.writerow(["RUNS_ON_Edges", total_events])
        writer.writerow(["EXECUTED_BY_Edges", int(total_events * 0.3)])
        writer.writerow(["INVOLVES_Edges", int(total_events * 0.12)])
        writer.writerow(["SPAWNED_Edges", int(len(process_identifiers) * 0.2)])
        writer.writerow(["PRECEDES_Edges", k3_edges])

    print(f"Max events per host: {max_events}")
    print(f"Max events within 1-hr window: {max_per_hour}")
    print(f"All pairs edges: {all_pairs_edges}")
    print(f"K=1 edges: {k1_edges}")
    print(f"K=3 edges: {k3_edges}")
    print(f"K=5 edges: {k5_edges}")
    print(f"K=10 edges: {k10_edges}")

if __name__ == "__main__":
    main()
