"""
DARPA OpTC Selective Enrichment and Labeling Pipeline

Downloads selected files representing attack paths/compromised hosts,
filters records for target red-team hosts (Stream-and-Discard policy),
normalizes eCAR records to SOCFusion V4 schema,
labels attack events based on ground-truth timestamps and signatures,
and merges them with existing telemetry into normalized_events_v5.csv.
"""

import os
import gzip
import json
import re
import logging
import gdown
import pandas as pd
from datetime import datetime, timezone

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# Output schema columns
COLUMNS_V4 = [
    'event_id', 'timestamp', 'original_timestamp', 'timestamp_end', 'host',
    'source', 'log_type', 'event_code', 'event_type', 'user', 'domain',
    'src_ip', 'dst_ip', 'src_port', 'dst_port', 'process_guid',
    'process_id', 'parent_process_guid', 'parent_process_id',
    'process_name', 'parent_process_name', 'command_line', 'image',
    'target_image', 'file_path', 'registry_path', 'service_name',
    'authentication_type', 'logon_type', 'logon_id', 'raw_message',
    'raw_event', 'technique_id', 'scenario', 'source_file'
]

# Google Drive Target Files for selective download
TARGET_FILES = [
    # Day 1: 23Sep19-red
    {"period": "23Sep19-red", "range": "AIA-201-225", "id": "1HFSyvmgH0jvdnnnTdKfWRjZYOrLWoIkv", "name": "AIA-201-225.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-401-425", "id": "1r4urs7OuKKTO6Y3-DOUMERwNasGEcRUN", "name": "AIA-401-425.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-651-675", "id": "13o8h42QM9Gzv84UyRNwlgc9oWicvxExZ", "name": "AIA-651-675.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-1-25",   "id": "1LCqw6oEiYRg5cRAAcI9Xu6eC5P8WJD90", "name": "AIA-1-25.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-101-125", "id": "1rCpvGh9uAwzzD54Uenvy7LSXmdMkPxML", "name": "AIA-101-125.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-251-275", "id": "18letRhacv_nIpYhIOxclYeGQ72oBjZen", "name": "AIA-251-275.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-301-325", "id": "16P63Eu7N23UzRXcW9DaDslwnjebPVL3D", "name": "AIA-301-325.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-351-375", "id": "1I6W_idcNW6iMlvg8pxPnQHcC4xOprIyq", "name": "AIA-351-375.ecar-last.json.gz"},
    {"period": "23Sep19-red", "range": "AIA-451-475", "id": "19puK2WsRQJyNIMrH4GqYLOXUwVSme0VG", "name": "AIA-451-475.ecar-last.json.gz"},
]

# Target red-team compromised or pivoting hosts
TARGET_HOSTS = {
    "sysclient0201", "sysclient0402", "sysclient0660", "dc1",
    "sysclient0104", "sysclient0170", "sysclient0205", "sysclient0255",
    "sysclient0321", "sysclient0355", "sysclient0419", "sysclient0462",
    "sysclient0503", "sysclient0559", "sysclient0609", "sysclient0771",
    "sysclient0874", "sysclient0955", "sysclient0501", "sysclient0811",
    "sysclient0005", "sysclient0010", "sysclient0051", "sysclient0351",
    "sysclient0069", "sysclient0203", "sysclient0358", "sysclient0618",
    "sysclient0851", "sysclient0974"
}

def download_file(file_info) -> str:
    """Download file if it does not already exist."""
    dest_dir = f"data/raw/optc/{file_info['period']}/{file_info['range']}"
    os.makedirs(dest_dir, exist_ok=True)
    dest_path = f"{dest_dir}/{file_info['name']}"
    
    if os.path.exists(dest_path):
        logger.info(f"File already exists: {dest_path}")
        return dest_path
        
    logger.info(f"Downloading {file_info['period']}/{file_info['range']}/{file_info['name']}...")
    try:
        gdown.download(id=file_info["id"], output=dest_path, quiet=True)
        logger.info(f"Successfully downloaded to {dest_path}")
    except Exception as e:
        logger.error(f"Download failed for ID {file_info['id']}: {e}")
    return dest_path

def _normalize_path(path: str) -> str:
    if not path:
        return ""
    path = re.sub(r"\\Device\\HarddiskVolume\d+\\", r"C:\\", path, flags=re.IGNORECASE)
    path = re.sub(r"/Device/HarddiskVolume\d+/", r"C:/", path, flags=re.IGNORECASE)
    return path

def _extract_name(path: str) -> str:
    if not path:
        return ""
    return re.split(r"[/\\]", path)[-1]

def _parse_timestamp(ts: str) -> str:
    if not ts:
        return ""
    try:
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except:
        return ts

def _is_tool(name: str, path_or_cmd: str) -> bool:
    """Check if the tool name (e.g. 'nc.exe' or 'plink.exe') is present as a whole word/filename in path/cmd."""
    if not path_or_cmd:
        return False
    # Check if the name exists with word boundaries or path separators
    import re
    # We match: start of string/path-separator/space/quote, followed by name, followed by end of string/space/quote/path-separator
    pattern = rf"(^|[/\s\\'\"]){re.escape(name.lower())}(\s|$|['\"])"
    return bool(re.search(pattern, path_or_cmd.lower()))

def label_event(host: str, ts_str: str, obj: str, action: str, cmdline: str, image: str, file_path: str, reg_path: str) -> str:
    """
    Apply MITRE ATT&CK label based on host, time-window, and signature/activity details.
    All times compared are parsed to datetimes.
    """
    if not ts_str:
        return ""
        
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except:
        return ""
        
    h = host.lower().split('.')[0]
    cmd = (cmdline or "").lower()
    img = (image or "").lower()
    fp = (file_path or "").lower()
    rp = (reg_path or "").lower()
    
    # Day 1: 09/23/2019
    # Attack started 11:20:00 EDT (15:20:00 UTC) to 16:00:00 EDT (20:00:00 UTC)
    d1_start = datetime.fromisoformat("2019-09-23T15:20:00+00:00")
    d1_end = datetime.fromisoformat("2019-09-23T20:00:00+00:00")
    
    # Day 2: 09/24/2019
    # Phishing macro stager execution 10:30 EDT (14:30 UTC) to 16:00 EDT (20:00 UTC)
    d2_start = datetime.fromisoformat("2019-09-24T14:30:00+00:00")
    d2_end = datetime.fromisoformat("2019-09-24T20:00:00+00:00")
    
    # Day 3: 09/25/2019
    # Malicious upgrade 10:00 EDT (14:00 UTC) to 14:00 EDT (18:00 UTC)
    d3_start = datetime.fromisoformat("2019-09-25T14:00:00+00:00")
    d3_end = datetime.fromisoformat("2019-09-25T18:00:00+00:00")

    # --- Day 1 Rules ---
    if d1_start <= dt <= d1_end:
        if h == "sysclient0201":
            if "runme.bat" in cmd or "news.com:8000" in cmd or "powershell" in img:
                if "powershell" in img and ("runme" in cmd or "news.com" in cmd):
                    return "T1059.001"
            if "windir" in rp and "environment" in rp:
                return "T1112"
            if "lsass" in cmd or "lsass" in fp or (obj == "PROCESS" and action == "OPEN" and "lsass" in img):
                return "T1003.001"
            if "currentversion\\debug" in rp or "run" in rp:
                return "T1112"
            if "wmic" in img or "wmic" in cmd:
                return "T1047"
            if "ping" in img or "ping" in cmd or "arp" in img or "arp" in cmd:
                return "T1016"
                
        elif h == "sysclient0402":
            if "wmic" in img or "wmic" in cmd or "powershell" in img:
                return "T1047"
            if "ping" in img or "ping" in cmd:
                return "T1016"
                
        elif h == "sysclient0660":
            if "ipconfig" in img or "ipconfig" in cmd:
                return "T1016"
            if "lsass" in img or "lsass" in cmd or (obj == "PROCESS" and action == "OPEN" and "lsass" in img):
                return "T1003.001"
            if "zipfldr.dll" in fp or "zipfldr.dll" in cmd:
                return "T1105"
            if "wmic" in img or "wmic" in cmd:
                return "T1047"
            if "powershell" in img and ("dc" in cmd or "domain" in cmd or "resolve" in cmd):
                return "T1087.002"
                
        elif h == "dc1":
            if "lsass" in img or "lsass" in cmd or (obj == "PROCESS" and action == "OPEN" and "lsass" in img):
                return "T1003.001"
            if "lsadump" in cmd:
                return "T1003.003"
            if "wmic" in img or "wmic" in cmd:
                return "T1047"
                
        # Lateral check-ins for the 14 workstations on Day 1
        elif h in {"sysclient0104", "sysclient0170", "sysclient0205", "sysclient0255", 
                   "sysclient0321", "sysclient0355", "sysclient0419", "sysclient0462", 
                   "sysclient0503", "sysclient0559", "sysclient0609", "sysclient0771", 
                   "sysclient0874", "sysclient0955"}:
            if "powershell" in img or "powershell" in cmd:
                return "T1059.001"
            if "wmic" in img or "wmic" in cmd:
                return "T1047"

    # --- Day 2 Rules ---
    elif d2_start <= dt <= d2_end:
        if h == "sysclient0501":
            if "winword" in cmd or "excel" in cmd or ("powershell" in img and "payroll" in cmd):
                return "T1059.001"
            if _is_tool("plink.exe", cmd) or _is_tool("plink.exe", img) or _is_tool("plink.exe", fp) or _is_tool("plink", cmd) or _is_tool("plink", img) or _is_tool("plink", fp):
                if obj == "FILE" and action == "CREATE":
                    return "T1105"
                return "T1021.006"
            if "wmic" in cmd or "subscription" in cmd or "persistence" in cmd:
                return "T1053.005"
            if "trusted documents" in rp or "findtrusteddocuments" in cmd:
                return "T1112"
                
        elif h == "sysclient0811":
            if "powershell" in img or "winword" in img or "payroll" in cmd:
                return "T1059.001"
                
        elif h == "sysclient0005":
            if _is_tool("nc.exe", cmd) or _is_tool("nc.exe", fp) or "movingonup" in cmd or "movingonup" in fp:
                return "T1105"
            if "rdp" in cmd or "mstsc" in img or "mstsc" in cmd:
                return "T1021.006"
                
        elif h == "sysclient0974":
            if "mstsc" in img or "mstsc" in cmd or "rdp" in cmd:
                return "T1021.006"
                
        elif h in {"sysclient0010", "sysclient0069", "sysclient0203", "sysclient0358", 
                   "sysclient0618", "sysclient0851"}:
            if "powershell" in img or "wmic" in cmd or "wmic" in img:
                return "T1047"

    # --- Day 3 Rules ---
    elif d3_start <= dt <= d3_end:
        if h == "sysclient0051":
            if "update.exe" in fp or "update.exe" in cmd or "notepad++" in cmd:
                return "T1105"
            if "powershell" in img or "cmd.exe" in img:
                return "T1059.001"
            if "lsass" in img or "lsass" in cmd or (obj == "PROCESS" and action == "OPEN" and "lsass" in img):
                return "T1003.001"
            if "arp" in cmd or "arp" in img or "ping" in img:
                return "T1016"
            if "autorun" in rp or "run" in rp:
                return "T1112"
            if "net" in img and ("user" in cmd or "add" in cmd):
                return "T1021.006"
                
        elif h == "sysclient0351":
            if "update.exe" in fp or "update.exe" in cmd or "notepad++" in cmd:
                return "T1105"
            if "powershell" in img or "cmd.exe" in img:
                return "T1059.001"
                
    # Signature-based fallback for any target host on target days
    if "mimikatz" in cmd:
        return "T1003.001"
    if "lsadump" in cmd:
        return "T1003.003"
    if _is_tool("plink.exe", cmd) or _is_tool("plink.exe", img):
        return "T1021.006"
    if _is_tool("nc.exe", cmd) or _is_tool("nc.exe", img):
        return "T1105"
        
    return ""

def parse_and_filter_file(filepath: str, period: str) -> pd.DataFrame:
    """Stream a file, apply filtering and labeling, return mapped DataFrame."""
    logger.info(f"Parsing and filtering: {filepath}")
    rows = []
    
    n_total = 0
    n_kept = 0
    n_labeled = 0
    
    target_hosts_lower = {h.lower() for h in TARGET_HOSTS}
    
    with gzip.open(filepath, "rt", errors="replace") as f:
        for line in f:
            n_total += 1
            if not line.strip():
                continue
                
            idx = line.find('"hostname":"')
            if idx == -1:
                continue
            start = idx + 12
            end = line.find('"', start)
            hostname = line[start:end]
            h_clean = hostname.lower().split(".")[0]
            if h_clean not in target_hosts_lower:
                continue
                
            try:
                raw = json.loads(line)
            except:
                continue
                
            n_kept += 1
            
            # Map eCAR event to SOCFusion Schema
            props = raw.get("properties", {}) or {}
            obj = raw.get("object", "")
            action = raw.get("action", "")
            
            # Extract fields
            event_id = raw.get("id")
            timestamp = _parse_timestamp(raw.get("timestamp"))
            original_timestamp = raw.get("timestamp")
            
            # Process info
            pid = str(raw.get("pid")) if raw.get("pid") is not None else None
            ppid = str(raw.get("ppid")) if raw.get("ppid") is not None else None
            
            image_path = _normalize_path(props.get("image_path") or props.get("image") or "")
            process_name = _extract_name(image_path)
            command_line = props.get("command_line") or props.get("commandLine") or ""
            
            # User & Domain
            user = props.get("user") or raw.get("principal") or ""
            domain = "systemia.com" if ".systemia.com" in hostname.lower() else ""
            
            # Network
            src_ip = props.get("src_ip") or props.get("src_addr") or props.get("local_addr") or ""
            dst_ip = props.get("dst_ip") or props.get("dst_addr") or props.get("remote_addr") or ""
            src_port = str(props.get("src_port") or props.get("local_port") or "")
            dst_port = str(props.get("dst_port") or props.get("remote_port") or "")
            
            # GUID mapping
            # Parent-child mapping using actorID / objectID
            actor_id = raw.get("actorID")
            object_id = raw.get("objectID")
            
            if obj == "PROCESS" and action == "CREATE":
                process_guid = object_id or ""
                parent_process_guid = actor_id or ""
            else:
                process_guid = actor_id or ""
                parent_process_guid = ""
                
            parent_process_name = ""
            
            image = image_path
            target_image = _normalize_path(props.get("target_image") or "")
            file_path = _normalize_path(props.get("file_path") or props.get("path") or "")
            registry_path = props.get("registry_path") or props.get("key") or ""
            
            event_code = f"{obj}:{action}"
            log_type = obj
            
            raw_event = line.strip()
            raw_message = f"OpTC normalized {event_code} event"
            
            # Label
            tech_id = label_event(
                h_clean, timestamp, obj, action, command_line, image_path, file_path, registry_path
            )
            
            if tech_id:
                n_labeled += 1
                
            rows.append({
                'event_id': event_id,
                'timestamp': timestamp,
                'original_timestamp': original_timestamp,
                'timestamp_end': None,
                'host': hostname,
                'source': "DARPA_OpTC_eCAR",
                'log_type': log_type,
                'event_code': event_code,
                'event_type': None,
                'user': user,
                'domain': domain,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'process_guid': process_guid,
                'process_id': pid,
                'parent_process_guid': parent_process_guid,
                'parent_process_id': ppid,
                'process_name': process_name,
                'parent_process_name': parent_process_name,
                'command_line': command_line,
                'image': image,
                'target_image': target_image,
                'file_path': file_path,
                'registry_path': registry_path,
                'service_name': None,
                'authentication_type': None,
                'logon_type': None,
                'logon_id': None,
                'raw_message': raw_message,
                'raw_event': raw_event,
                'technique_id': tech_id if tech_id else None,
                'scenario': "DARPA_OpTC",
                'source_file': f"{period}/{filepath.split('/')[-1]}"
            })
            
    df = pd.DataFrame(rows, columns=COLUMNS_V4)
    logger.info(f"Done: {filepath} | Total parsed: {n_total} | Target host events kept: {n_kept} | Labeled attacks: {n_labeled}")
    return df

def main():
    logger.info("Starting OpTC Selective Acquisition and Enrichment Pipeline...")
    
    # 1. Download target files
    local_paths = []
    for f_info in TARGET_FILES:
        path = download_file(f_info)
        local_paths.append((path, f_info["period"]))
        
    # 2. Parse and filter each file to dataframes
    all_dfs = []
    for filepath, period in local_paths:
        df = parse_and_filter_file(filepath, period)
        if not df.empty:
            all_dfs.append(df)
            
    if not all_dfs:
        logger.error("No events were parsed. Enrichment aborted.")
        return
        
    optc_df = pd.concat(all_dfs, ignore_index=True)
    logger.info(f"Total OpTC Enriched Events: {len(optc_df)}")
    logger.info(f"Hosts covered: {optc_df['host'].nunique()}")
    logger.info(f"Labeled attacks by technique:\n{optc_df['technique_id'].value_counts(dropna=False)}")
    
    # Save the optc parsed dataset for validation before final merge
    optc_path = "data/processed/optc_parsed_enriched.csv"
    optc_df.to_csv(optc_path, index=False)
    logger.info(f"Saved intermediate parsed OpTC events to {optc_path}")
    
    # 3. Merge with existing v4 dataset
    v4_path = "data/processed/normalized_events_v4.csv"
    v5_path = "data/processed/normalized_events_v5.csv"
    
    if os.path.exists(v4_path):
        logger.info(f"Merging with existing dataset: {v4_path}...")
        # Since v4 is 9.4 million rows, we copy it in chunks to v5 to avoid OOM
        chunk_size = 500000
        first_chunk = True
        
        # Open v5 in write mode (overwrite if exists)
        for chunk in pd.read_csv(v4_path, chunksize=chunk_size, low_memory=False):
            if first_chunk:
                chunk.to_csv(v5_path, index=False, mode="w")
                first_chunk = False
            else:
                chunk.to_csv(v5_path, index=False, mode="a", header=False)
        
        # Append the new OpTC events
        optc_df.to_csv(v5_path, index=False, mode="a", header=False)
        logger.info(f"Successfully created merged dataset at {v5_path}")
    else:
        logger.warning(f"V4 dataset not found at {v4_path}. Writing parsed OpTC events directly to {v5_path}")
        optc_df.to_csv(v5_path, index=False)
        
    # Count rows of new dataset
    v5_count = 0
    if os.path.exists(v5_path):
        with open(v5_path, "r") as f:
            for _ in f:
                v5_count += 1
    logger.info(f"Final merged dataset row count: {v5_count}")
    logger.info("Pipeline execution complete.")

if __name__ == "__main__":
    main()
