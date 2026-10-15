import os
import csv
import time
import json
import re
import time
import json
from collections import Counter, defaultdict
from src.data.parsers.sysmon_parser import SysmonXMLParser
from src.data.parsers.windows_kv_parser import WindowsKVParser
from src.data.parsers.json_parser import JSONParser
from src.data.normalize import create_empty_event

RAW_DIR = "/home/vikas/SOCFusion/data/raw/splunk_attack_data"
PROCESSED_DIR = "/home/vikas/SOCFusion/data/processed"

def determine_parser(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = []
            for _ in range(50):
                line = f.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    lines.append(line)
                    if len(lines) >= 5:
                        break
            
            if any(l.startswith('<Event') or l.startswith('<?xml') or '<System>' in l for l in lines):
                return SysmonXMLParser(), "SysmonXMLParser"
                
            if any(l.startswith('{') and l.endswith('}') for l in lines):
                return JSONParser(), "JSONParser"
                
            if any(re.match(r'^(?:\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}(?: [AP]M)?|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})', l) or 'LogName=' in l or 'EventCode=' in l for l in lines):
                return WindowsKVParser(), "WindowsKVParser"
                
            filename = os.path.basename(filepath).lower()
            if filename.endswith(".json"):
                return JSONParser(), "JSONParser"
            if filename.endswith(".log"):
                return WindowsKVParser(), "WindowsKVParser"
    except Exception:
        pass
    return None, "None"

def extract_provenance(filepath, base_dir):
    rel_path = os.path.relpath(filepath, base_dir)
    parts = rel_path.split(os.sep)
    technique_id = parts[0] if len(parts) > 0 else "unknown"
    scenario = parts[1] if len(parts) > 2 else "default"
    return technique_id, scenario, rel_path

def main():
    start_time = time.time()
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    output_file = os.path.join(PROCESSED_DIR, "normalized_events_v4.csv")
    error_file = os.path.join(PROCESSED_DIR, "parse_errors_v4.csv")
    
    stats = {
        "total_source_files_discovered": 0,
        "total_telemetry_files_processed": 0,
        "files_successfully_processed": 0,
        "files_with_parsing_failures": 0,
        "total_valid_events": 0,
        "total_parse_errors": 0,
        "timestamp_parsing_success": 0,
        "timestamp_parsing_failure": 0,
    }
    
    events_by_technique = Counter()
    events_by_log_type = Counter()
    events_by_source_file = Counter()
    missing_value_stats = Counter()
    parser_usage = Counter()
    
    empty_event_keys = list(create_empty_event().keys())
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f_out, \
         open(error_file, 'w', newline='', encoding='utf-8') as f_err:
         
        writer = csv.DictWriter(f_out, fieldnames=empty_event_keys)
        writer.writeheader()
        
        error_writer = csv.DictWriter(f_err, fieldnames=['source_file', 'line_no', 'error_type', 'error_message'])
        error_writer.writeheader()
        
        for root, _, files in os.walk(RAW_DIR):
            for file in files:
                filepath = os.path.join(root, file)
                stats["total_source_files_discovered"] += 1
                
                if file.endswith((".tar.gz", ".zip", ".yml", ".md")):
                    continue
                    
                parser, parser_name = determine_parser(filepath)
                if not parser:
                    continue
                
                stats["total_telemetry_files_processed"] += 1
                parser_usage[parser_name] += 1
                technique_id, scenario, rel_path = extract_provenance(filepath, RAW_DIR)
                
                file_has_error = False
                file_has_success = False
                
                try:
                    for event in parser.parse(filepath, technique_id, scenario, rel_path):
                        if 'error' in event:
                            error_writer.writerow({
                                'source_file': event.get('source_file', rel_path),
                                'line_no': event.get('line_no', 'unknown'),
                                'error_type': 'ParseError',
                                'error_message': event.get('error', 'unknown error')
                            })
                            stats["total_parse_errors"] += 1
                            file_has_error = True
                        else:
                            writer.writerow(event)
                            stats["total_valid_events"] += 1
                            file_has_success = True
                            
                            events_by_technique[technique_id] += 1
                            events_by_log_type[event.get('log_type', 'unknown')] += 1
                            events_by_source_file[rel_path] += 1
                            
                            if event.get('timestamp'):
                                stats["timestamp_parsing_success"] += 1
                            else:
                                stats["timestamp_parsing_failure"] += 1
                                
                            for field in ["host", "user", "process_id", "command_line", "src_ip"]:
                                if not event.get(field):
                                    missing_value_stats[field] += 1
                except Exception as e:
                    error_writer.writerow({
                        'source_file': rel_path,
                        'line_no': 'file_level',
                        'error_type': 'CatastrophicParseError',
                        'error_message': str(e)
                    })
                    stats["total_parse_errors"] += 1
                    file_has_error = True
                
                if file_has_error:
                    stats["files_with_parsing_failures"] += 1
                if file_has_success:
                    stats["files_successfully_processed"] += 1
                    
    duration = time.time() - start_time
    
    report = {
        "stats": stats,
        "events_by_technique": dict(events_by_technique),
        "events_by_log_type": dict(events_by_log_type),
        "events_by_source_file": dict(events_by_source_file),
        "missing_value_stats": dict(missing_value_stats),
        "parser_usage": dict(parser_usage),
        "duration_seconds": duration,
        "output_sizes": {
            "normalized_events_v4.csv": os.path.getsize(output_file),
            "parse_errors_v4.csv": os.path.getsize(error_file)
        }
    }
    
    with open(os.path.join(PROCESSED_DIR, "run_metrics_v4.json"), 'w') as f:
        json.dump(report, f, indent=2)
        
    print(f"Processing complete in {duration:.2f}s")
    print(f"Output saved to {output_file}")

if __name__ == '__main__':
    main()
