import re
from dateutil import parser as dt_parser

def create_empty_event():
    return {
        "event_id": "",
        "timestamp": "",
        "original_timestamp": "",
        "timestamp_end": "",
        "host": "",
        "source": "",
        "log_type": "",
        "event_code": "",
        "event_type": "",
        "user": "",
        "domain": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": "",
        "dst_port": "",
        "process_guid": "",
        "process_id": "",
        "parent_process_guid": "",
        "parent_process_id": "",
        "process_name": "",
        "parent_process_name": "",
        "command_line": "",
        "image": "",
        "target_image": "",
        "file_path": "",
        "registry_path": "",
        "service_name": "",
        "authentication_type": "",
        "logon_type": "",
        "logon_id": "",
        "raw_message": "",
        "raw_event": "",
        "technique_id": "",
        "scenario": "",
        "source_file": ""
    }

def normalize_timestamp(ts_str):
    if not ts_str:
        return ""
        
    ts_str = str(ts_str).strip()
    
    import datetime
    
    if re.match(r'^\d{10,13}(?:\.\d+)?$', ts_str):
        try:
            val = float(ts_str)
            if val > 100000000000:
                seconds = val / 1000.0
            else:
                seconds = val
            dt = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
            
            if '.' in ts_str:
                frac = ts_str.split('.')[1]
            elif val > 100000000000:
                frac = ts_str[-3:]
            else:
                frac = ""
            base = dt.strftime("%Y-%m-%dT%H:%M:%S")
            return f"{base}.{frac}Z" if frac else f"{base}Z"
        except Exception:
            return ""

    try:
        clean_ts = ts_str.replace(" UTC", "")
        dt = dt_parser.parse(clean_ts)
        if dt.tzinfo:
            dt = dt.astimezone(datetime.timezone.utc)
        
        frac_match = re.search(r'\.(\d+)', ts_str)
        if frac_match:
            fraction = frac_match.group(1)
            return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction}Z"
        else:
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            
    except Exception:
        return ""
