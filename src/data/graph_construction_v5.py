import os
import csv
import sys
import pickle
import numpy as np

def main():
    csv.field_size_limit(sys.maxsize)
    
    FEATURES_CSV = "data/processed/features_v4/features.csv"
    SCHEMA_JSON = "data/processed/features_v4/feature_schema.json"
    HOST_PART = "data/analysis/split_v2/host_partition.csv"
    
    OUT_DIR = "data/processed/graphs_v5"
    ANALYSIS_DIR = "data/analysis/graph_v5"
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(ANALYSIS_DIR, exist_ok=True)
    
    import json
    with open(SCHEMA_JSON, 'r') as f:
        schema = json.load(f)
        
    num_features = schema['num_features']
    feature_fields = schema['feature_fields']
    ohe_fields = schema['ohe_fields']
    
    # Load labels
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    # Load host partitions
    host_to_part = {}
    with open(HOST_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_to_part[row['host']] = row['partition']
            
    graphs = {
        'train': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                            'Host': {'num_nodes': 0},
                            'User': {'num_nodes': 0},
                            'Process': {'num_nodes': 0}},
                  'edges': {'INVOLVES': {'edge_index': [[], []]},
                            'SPAWNED': {'edge_index': [[], []]}},
                  'maps': {'Event': {}, 'Host': {}, 'User': {}, 'Process': {}}},
        'val': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                          'Host': {'num_nodes': 0},
                          'User': {'num_nodes': 0},
                          'Process': {'num_nodes': 0}},
                'edges': {'INVOLVES': {'edge_index': [[], []]},
                          'SPAWNED': {'edge_index': [[], []]}},
                'maps': {'Event': {}, 'Host': {}, 'User': {}, 'Process': {}}},
        'test': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                           'Host': {'num_nodes': 0},
                           'User': {'num_nodes': 0},
                           'Process': {'num_nodes': 0}},
                 'edges': {'INVOLVES': {'edge_index': [[], []]},
                           'SPAWNED': {'edge_index': [[], []]}},
                 'maps': {'Event': {}, 'Host': {}, 'User': {}, 'Process': {}}}
    }
    
    def get_node_id(part, ntype, raw_id):
        m = graphs[part]['maps'][ntype]
        if raw_id not in m:
            m[raw_id] = graphs[part]['nodes'][ntype]['num_nodes']
            graphs[part]['nodes'][ntype]['num_nodes'] += 1
        return m[raw_id]
        
    print("Streaming and building graphs V5...")
    with open(FEATURES_CSV, 'r') as f:
        reader = csv.DictReader(f)
        
        for i, row in enumerate(reader):
            host = row.get('host', '').strip()
            if not host: host = 'UNKNOWN_HOST'
            part = host_to_part.get(host)
            
            if not part:
                continue
                
            feat_vec = [float(row[f]) for f in feature_fields] + [float(row[f]) for f in ohe_fields]
            
            tid = row.get('technique_id', '')
            label = label_map.get(tid, -1)
            
            e_id = get_node_id(part, 'Event', i)
            graphs[part]['nodes']['Event']['x'].append(feat_vec)
            graphs[part]['nodes']['Event']['y'].append(label)
            
            # Process Edges
            process_id = row.get('process_id', '').strip()
            if process_id:
                p_id = get_node_id(part, 'Process', f"{host}_{process_id}")
                graphs[part]['edges']['INVOLVES']['edge_index'][0].append(e_id)
                graphs[part]['edges']['INVOLVES']['edge_index'][1].append(p_id)
                
                parent_process_id = row.get('parent_process_id', '').strip()
                if parent_process_id:
                    pp_id = get_node_id(part, 'Process', f"{host}_{parent_process_id}")
                    # SPAWNED: Parent -> Process
                    graphs[part]['edges']['SPAWNED']['edge_index'][0].append(pp_id)
                    graphs[part]['edges']['SPAWNED']['edge_index'][1].append(p_id)

    print("Writing pt files...")
    
    # Track A classes
    TRACK_A_CLASSES = [
        "T1003.001", "T1003.003", "T1016", "T1021.006", "T1047", "T1053.005",
        "T1059.001", "T1087.002", "T1105", "T1112", "T1558.003", "T1562.001"
    ]
    track_a_mapped = [label_map[t] for t in TRACK_A_CLASSES]
    
    report = "# Graph V5 Construction Report\n\n"
    
    for part in ['train', 'val', 'test']:
        d = graphs[part]
        
        out_dict = {
            'nodes': d['nodes'],
            'edges': {
                ('Event', 'INVOLVES', 'Process'): {
                    'edge_index': d['edges']['INVOLVES']['edge_index']
                },
                ('Process', 'SPAWNED', 'Process'): {
                    'edge_index': d['edges']['SPAWNED']['edge_index']
                }
            }
        }
        
        y_tensor = np.array(d['nodes']['Event']['y'])
        valid_mask = np.isin(y_tensor, track_a_mapped)
        num_track_a = valid_mask.sum()
        
        report += f"## Partition: {part}\n"
        report += f"- Event Nodes: {d['nodes']['Event']['num_nodes']}\n"
        report += f"- Process Nodes: {d['nodes']['Process']['num_nodes']}\n"
        report += f"- INVOLVES Edges: {len(d['edges']['INVOLVES']['edge_index'][0])}\n"
        report += f"- SPAWNED Edges: {len(d['edges']['SPAWNED']['edge_index'][0])}\n"
        report += f"- Feature Dimension: {len(feat_vec)}\n"
        report += f"- Track A Labeled Events: {num_track_a}\n\n"
        
        filepath = os.path.join(OUT_DIR, f"{part}_data.pt")
        with open(filepath, 'wb') as f:
            pickle.dump(out_dict, f)
            
    with open(os.path.join(ANALYSIS_DIR, "graph_v5_report.md"), "w") as f:
        f.write(report)
        
    print("Graph V5 generation complete.")

if __name__ == "__main__":
    main()
