import os
import csv
import sys
import pickle
import numpy as np

def main():
    csv.field_size_limit(sys.maxsize)
    
    FEATURES_CSV = "data/processed/features_synthetic_v2/features.csv"
    SCHEMA_JSON = "data/processed/features_synthetic_v2/feature_schema.json"
    HOST_PART = "data/processed/synthetic_attack_v2/synthetic_host_partition.csv"
    
    OUT_DIR = "data/processed/graphs_synthetic_v2"
    os.makedirs(OUT_DIR, exist_ok=True)
    
    import json
    with open(SCHEMA_JSON, 'r') as f:
        schema = json.load(f)
        
    num_features = schema['num_features']
    feature_fields = schema['feature_fields']
    ohe_fields = schema['ohe_fields']
    
    LABEL_MAP_JSON = "data/processed/graphs_v1/label_mapping.json"
    with open(LABEL_MAP_JSON, 'r') as f:
        label_map = json.load(f)
        
    host_to_part = {}
    with open(HOST_PART, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            host_to_part[row['host']] = row['partition']
            
    graphs = {
        'train': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                            'Process': {'num_nodes': 0}},
                  'edges': {'INVOLVES': {'edge_index': [[], []]},
                            'SPAWNED': {'edge_index': [[], []]}},
                  'maps': {'Event': {}, 'Process': {}}},
        'val': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                          'Process': {'num_nodes': 0}},
                'edges': {'INVOLVES': {'edge_index': [[], []]},
                          'SPAWNED': {'edge_index': [[], []]}},
                'maps': {'Event': {}, 'Process': {}}},
        'test': {'nodes': {'Event': {'x': [], 'y': [], 'num_nodes': 0},
                           'Process': {'num_nodes': 0}},
                 'edges': {'INVOLVES': {'edge_index': [[], []]},
                           'SPAWNED': {'edge_index': [[], []]}},
                 'maps': {'Event': {}, 'Process': {}}}
    }
    
    def get_node_id(part, ntype, raw_id):
        m = graphs[part]['maps'][ntype]
        if raw_id not in m:
            m[raw_id] = graphs[part]['nodes'][ntype]['num_nodes']
            graphs[part]['nodes'][ntype]['num_nodes'] += 1
        return m[raw_id]
        
    print("Streaming and building Synthetic V2 Graphs...")
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
            
            process_id = row.get('process_id', '').strip()
            if process_id:
                p_id = get_node_id(part, 'Process', f"{host}_{process_id}")
                graphs[part]['edges']['INVOLVES']['edge_index'][0].append(e_id)
                graphs[part]['edges']['INVOLVES']['edge_index'][1].append(p_id)
                
                parent_process_id = row.get('parent_process_id', '').strip()
                if parent_process_id:
                    pp_id = get_node_id(part, 'Process', f"{host}_{parent_process_id}")
                    graphs[part]['edges']['SPAWNED']['edge_index'][0].append(pp_id)
                    graphs[part]['edges']['SPAWNED']['edge_index'][1].append(p_id)

    print("Writing pt files...")
    
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
                },
                ('Process', 'rev_INVOLVES', 'Event'): {
                    'edge_index': [d['edges']['INVOLVES']['edge_index'][1], d['edges']['INVOLVES']['edge_index'][0]]
                }
            }
        }
        
        filepath = os.path.join(OUT_DIR, f"{part}_data.pt")
        with open(filepath, 'wb') as f:
            pickle.dump(out_dict, f)
            
    print("Synthetic V2 Graph generation complete.")

if __name__ == "__main__":
    main()
