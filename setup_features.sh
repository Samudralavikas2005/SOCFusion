mkdir -p src/data/features/
touch src/data/features/__init__.py

cat << 'INNER_EOF' > src/data/features/temporal.py
import math
from dateutil import parser as dt_parser

def extract_temporal(ts_str):
    if not ts_str:
        return {'hour_sin': 0.0, 'hour_cos': 0.0, 'day_of_week_sin': 0.0, 'day_of_week_cos': 0.0}
    try:
        dt = dt_parser.parse(ts_str)
        hour = dt.hour + dt.minute / 60.0
        dow = dt.weekday() # 0-6
        return {
            'hour_sin': round(math.sin(2 * math.pi * hour / 24.0), 4),
            'hour_cos': round(math.cos(2 * math.pi * hour / 24.0), 4),
            'day_of_week_sin': round(math.sin(2 * math.pi * dow / 7.0), 4),
            'day_of_week_cos': round(math.cos(2 * math.pi * dow / 7.0), 4)
        }
    except Exception:
        return {'hour_sin': 0.0, 'hour_cos': 0.0, 'day_of_week_sin': 0.0, 'day_of_week_cos': 0.0}
INNER_EOF

cat << 'INNER_EOF' > src/data/features/text.py
import math
import re

def shannon_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return round(entropy, 4)

def extract_text_features(raw_message, cmd_line):
    raw_message = raw_message or ""
    cmd_line = cmd_line or ""
    
    ps_token_count = len(raw_message.split())
    msg_length = len(raw_message)
    cmd_length = len(cmd_line)
    cmd_entropy = shannon_entropy(cmd_line)
    
    ps_b64_indicator = 1 if re.search(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?', raw_message) else 0
    
    return {
        'msg_length': msg_length,
        'ps_token_count': ps_token_count,
        'cmd_length': cmd_length,
        'cmd_entropy': cmd_entropy,
        'ps_b64_indicator': ps_b64_indicator
    }
INNER_EOF

cat << 'INNER_EOF' > src/data/features/process.py
def extract_process_features(process_name):
    process_name = (process_name or "").lower()
    lolbins = ['powershell', 'cmd', 'wscript', 'cscript', 'mshta', 'rundll32', 'regsvr32', 'certutil', 'bitsadmin', 'bash', 'sh']
    is_lolbin = 0
    for l in lolbins:
        if l in process_name:
            is_lolbin = 1
            break
    return {
        'is_lolbin': is_lolbin
    }
INNER_EOF

cat << 'INNER_EOF' > src/data/features/missingness.py
def extract_missingness(row):
    return {
        'has_process_id': 1 if row.get('process_id') else 0,
        'has_user': 1 if row.get('user') else 0,
        'has_command_line': 1 if row.get('command_line') else 0
    }
INNER_EOF

cat << 'INNER_EOF' > src/data/features/schema.py
import json

def generate_schema(output_path):
    schema = [
        {"feature_name": "event_id", "source_column": "raw_event+timestamp", "type": "string", "description": "Deterministic UUID", "encoding": "hash", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": False},
        {"feature_name": "technique_id", "source_column": "technique_id", "type": "string", "description": "Target label", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        {"feature_name": "scenario", "source_column": "scenario", "type": "string", "description": "Provenance", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        {"feature_name": "source_file", "source_column": "source_file", "type": "string", "description": "Provenance", "encoding": "none", "missing_value_policy": "none", "leakage_risk": "critical", "allowed_for_model": False},
        
        {"feature_name": "hour_sin", "source_column": "timestamp", "type": "float", "description": "Cyclical hour", "encoding": "sin", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "hour_cos", "source_column": "timestamp", "type": "float", "description": "Cyclical hour", "encoding": "cos", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "day_of_week_sin", "source_column": "timestamp", "type": "float", "description": "Cyclical DOW", "encoding": "sin", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "day_of_week_cos", "source_column": "timestamp", "type": "float", "description": "Cyclical DOW", "encoding": "cos", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "log_type_idx", "source_column": "log_type", "type": "int", "description": "Categorical Log Type", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "event_code_idx", "source_column": "event_code", "type": "int", "description": "Categorical Event Code", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "source_idx", "source_column": "source", "type": "int", "description": "Categorical Source", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "process_name_idx", "source_column": "process_name", "type": "int", "description": "Categorical Process Name", "encoding": "ordinal", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "is_lolbin", "source_column": "process_name", "type": "int", "description": "Binary LOLBin indicator", "encoding": "binary", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "msg_length", "source_column": "raw_message", "type": "int", "description": "Raw message length", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "ps_token_count", "source_column": "raw_message", "type": "int", "description": "Space-separated token count", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "cmd_length", "source_column": "command_line", "type": "int", "description": "Command line length", "encoding": "numeric", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "cmd_entropy", "source_column": "command_line", "type": "float", "description": "Command line entropy", "encoding": "numeric", "missing_value_policy": "0.0", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "ps_b64_indicator", "source_column": "raw_message", "type": "int", "description": "Base64 block indicator", "encoding": "binary", "missing_value_policy": "0", "leakage_risk": "low", "allowed_for_model": True},
        
        {"feature_name": "has_process_id", "source_column": "process_id", "type": "int", "description": "PID present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "has_user", "source_column": "user", "type": "int", "description": "User present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True},
        {"feature_name": "has_command_line", "source_column": "command_line", "type": "int", "description": "Cmdline present", "encoding": "binary", "missing_value_policy": "none", "leakage_risk": "low", "allowed_for_model": True}
    ]
    with open(output_path, 'w') as f:
        json.dump(schema, f, indent=2)
INNER_EOF

cat << 'INNER_EOF' > src/data/feature_engineering.py
import csv
import sys
import os
import hashlib
import json
import time

from src.data.features.temporal import extract_temporal
from src.data.features.text import extract_text_features
from src.data.features.process import extract_process_features
from src.data.features.missingness import extract_missingness
from src.data.features.schema import generate_schema

def main():
    csv.field_size_limit(sys.maxsize)
    INPUT_FILE = "data/processed/normalized_events_v4.csv"
    if not os.path.exists(INPUT_FILE):
        INPUT_FILE = "data/processed/normalized_events_v2.csv"
        
    OUTPUT_DIR = "data/processed/features_v1/"
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    print("Pass 1: Building categorical vocabularies...")
    vocab_sets = {
        'log_type': set(),
        'event_code': set(),
        'source': set(),
        'process_name': set()
    }
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            for k in vocab_sets:
                val = row.get(k)
                if val:
                    vocab_sets[k].add(val)
                    
    vocabs = {}
    for k, vset in vocab_sets.items():
        sorted_vals = sorted(list(vset))
        vocabs[k] = {val: idx for idx, val in enumerate(sorted_vals, start=1)}
        
    with open(os.path.join(OUTPUT_DIR, "vocab.json"), 'w') as f:
        json.dump(vocabs, f, indent=2)
        
    generate_schema(os.path.join(OUTPUT_DIR, "feature_schema.json"))
    
    print("Pass 2: Extracting features...")
    
    stats = {
        'total_events': 0,
        'nan_count': 0,
        'infinite_count': 0
    }
    
    fieldnames = [
        "event_id", "technique_id", "scenario", "source_file",
        "hour_sin", "hour_cos", "day_of_week_sin", "day_of_week_cos",
        "log_type_idx", "event_code_idx", "source_idx", "process_name_idx",
        "is_lolbin", "msg_length", "ps_token_count", "cmd_length", "cmd_entropy", "ps_b64_indicator",
        "has_process_id", "has_user", "has_command_line"
    ]
    
    with open(INPUT_FILE, 'r', encoding='utf-8') as fin, \
         open(os.path.join(OUTPUT_DIR, "features.csv"), 'w', encoding='utf-8', newline='') as fout:
         
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=fieldnames)
        writer.writeheader()
        
        for row in reader:
            stats['total_events'] += 1
            
            raw = row.get('raw_event', '')
            ts = row.get('timestamp', '')
            id_str = raw + ts + row.get('log_type', '') + row.get('host', '') + row.get('event_code', '')
            event_id = hashlib.md5(id_str.encode('utf-8')).hexdigest()
            
            t_feats = extract_temporal(ts)
            
            c_feats = {
                'log_type_idx': vocabs['log_type'].get(row.get('log_type'), 0),
                'event_code_idx': vocabs['event_code'].get(row.get('event_code'), 0),
                'source_idx': vocabs['source'].get(row.get('source'), 0),
                'process_name_idx': vocabs['process_name'].get(row.get('process_name'), 0)
            }
            
            txt_feats = extract_text_features(row.get('raw_message', ''), row.get('command_line', ''))
            p_feats = extract_process_features(row.get('process_name', ''))
            m_feats = extract_missingness(row)
            
            out_row = {
                'event_id': event_id,
                'technique_id': row.get('technique_id', ''),
                'scenario': row.get('scenario', ''),
                'source_file': row.get('source_file', '')
            }
            out_row.update(t_feats)
            out_row.update(c_feats)
            out_row.update(txt_feats)
            out_row.update(p_feats)
            out_row.update(m_feats)
            
            writer.writerow(out_row)
            
    with open(os.path.join(OUTPUT_DIR, "feature_statistics.json"), 'w') as f:
        json.dump(stats, f, indent=2)
        
    print("Feature engineering complete.")

if __name__ == "__main__":
    main()
INNER_EOF
