import os
import csv
from src.data.parsers.sysmon_parser import SysmonXMLParser
from src.data.parsers.windows_kv_parser import WindowsKVParser
from src.data.parsers.json_parser import JSONParser
from src.data.normalize import create_empty_event

RAW_DIR = "/home/vikas/SOCFusion/data/raw/splunk_attack_data"
PROCESSED_DIR = "/home/vikas/SOCFusion/data/processed"

def determine_parser(filepath):
    filename = os.path.basename(filepath).lower()
    if filename.endswith(".json"):
        return JSONParser()
    elif filename == "windows-sysmon.log":
        return SysmonXMLParser()
    elif filename in ["windows-security.log", "windows-powershell.log", "windows-system.log"]:
        return WindowsKVParser()
    if filename.endswith(".log"):
        return WindowsKVParser()
    return None

def extract_provenance(filepath, base_dir):
    rel_path = os.path.relpath(filepath, base_dir)
    parts = rel_path.split(os.sep)
    technique_id = parts[0] if len(parts) > 0 else "unknown"
    scenario = parts[1] if len(parts) > 2 else "default"
    return technique_id, scenario, rel_path

def main():
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    actual_samples = []
    sysmon_found = kv_sec_found = kv_ps_found = json_found = False
    
    for root, _, files in os.walk(RAW_DIR):
        for file in files:
            filepath = os.path.join(root, file)
            if not sysmon_found and file == "windows-sysmon.log":
                actual_samples.append(filepath)
                sysmon_found = True
            elif not kv_sec_found and file == "windows-security.log":
                actual_samples.append(filepath)
                kv_sec_found = True
            elif not kv_ps_found and file == "windows-powershell.log":
                actual_samples.append(filepath)
                kv_ps_found = True
            elif not json_found and file.endswith(".json"):
                actual_samples.append(filepath)
                json_found = True
            
            if len(actual_samples) == 4:
                break
        if len(actual_samples) == 4:
            break
            
    print(f"Selected samples for validation:")
    for s in actual_samples:
        print(f"  - {s}")
    
    output_file = os.path.join(PROCESSED_DIR, "sample_normalized_events.csv")
    error_file = os.path.join(PROCESSED_DIR, "sample_parse_errors.csv")
    
    events_written = 0
    errors_written = 0
    
    fieldnames = list(create_empty_event().keys())
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f_out, \
         open(error_file, 'w', newline='', encoding='utf-8') as f_err:
         
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()
        
        error_writer = csv.DictWriter(f_err, fieldnames=['source_file', 'line_no', 'error_type', 'error_message'])
        error_writer.writeheader()
        
        for sample_path in actual_samples:
            parser = determine_parser(sample_path)
            if not parser:
                print(f"No parser for {sample_path}")
                continue
                
            technique_id, scenario, rel_path = extract_provenance(sample_path, RAW_DIR)
            print(f"Parsing {rel_path} with {parser.__class__.__name__}...")
            
            count = 0
            for event in parser.parse(sample_path, technique_id, scenario, rel_path):
                if 'error' in event:
                    error_writer.writerow({
                        'source_file': event['source_file'],
                        'line_no': event['line_no'],
                        'error_type': 'ParseError',
                        'error_message': event['error']
                    })
                    errors_written += 1
                else:
                    writer.writerow(event)
                    events_written += 1
                count += 1
                if count >= 5: # Keep sample small: 5 events per file
                    break
    
    print(f"\\nValidation run complete.")
    print(f"Wrote {events_written} events and {errors_written} errors.")
    print(f"Output: {output_file}")
    print(f"Errors: {error_file}")

if __name__ == '__main__':
    main()
