"""
DARPA OpTC Dataset Integrity and Label Audit Tool

Verifies the integrity of the downloaded gzipped NDJSON files,
analyzes the retained dataset statistics (event counts, PIDs, UUIDs),
validates process-tree relationships, and audits technique labels
against the official red-team ground truth PDF evidence.
"""

import os
import gzip
import json
import hashlib
import pandas as pd
import numpy as np
from datetime import datetime, timezone
import subprocess

# Directories
RAW_DIR = "data/raw/optc/23Sep19-red"
PARSED_CSV = "data/processed/optc_parsed_enriched.csv"
OUT_DIR = "data/analysis/optc_selective"

# Target files expected
EXPECTED_FILES = [
    "AIA-201-225/AIA-201-225.ecar-last.json.gz",
    "AIA-401-425/AIA-401-425.ecar-last.json.gz",
    "AIA-651-675/AIA-651-675.ecar-last.json.gz",
    "AIA-1-25/AIA-1-25.ecar-last.json.gz",
    "AIA-101-125/AIA-101-125.ecar-last.json.gz",
    "AIA-251-275/AIA-251-275.ecar-last.json.gz",
    "AIA-301-325/AIA-301-325.ecar-last.json.gz",
    "AIA-351-375/AIA-351-375.ecar-last.json.gz",
    "AIA-451-475/AIA-451-475.ecar-last.json.gz",
]

def get_file_hash(filepath: str) -> str:
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def verify_gzip_integrity(filepath: str) -> bool:
    try:
        # Run gzip -t to check integrity
        res = subprocess.run(["gzip", "-t", filepath], capture_output=True)
        return res.returncode == 0
    except Exception as e:
        print(f"Error checking gzip integrity for {filepath}: {e}")
        return False

def audit_downloads():
    print("--- Auditing Downloads ---")
    os.makedirs(OUT_DIR, exist_ok=True)
    
    rows = []
    all_ok = True
    
    for rel_path in EXPECTED_FILES:
        full_path = os.path.join(RAW_DIR, rel_path)
        if not os.path.exists(full_path):
            print(f"File missing: {full_path}")
            rows.append({
                "file": rel_path,
                "status": "MISSING",
                "size_mb": 0.0,
                "sha256": "N/A",
                "gzip_ok": False
            })
            all_ok = False
            continue
            
        size_bytes = os.path.getsize(full_path)
        size_mb = size_bytes / (1024.0 * 1024.0)
        gzip_ok = verify_gzip_integrity(full_path)
        sha256 = get_file_hash(full_path)
        
        status = "OK" if gzip_ok else "TRUNCATED/CORRUPT"
        if not gzip_ok:
            all_ok = False
            
        rows.append({
            "file": rel_path,
            "status": status,
            "size_mb": size_mb,
            "sha256": sha256,
            "gzip_ok": gzip_ok
        })
        print(f"{rel_path}: {status} | Size: {size_mb:.2f} MB | Gzip OK: {gzip_ok}")
        
    # Write download_integrity.md
    md_content = "# OpTC Download Integrity Verification\n\n"
    md_content += f"**Date/Time of Verification:** {datetime.now(timezone.utc).isoformat()}\n\n"
    md_content += "| File Path | Status | Compressed Size (MB) | SHA-256 Checksum | Gzip Integrity |\n"
    md_content += "| :--- | :--- | :--- | :--- | :--- |\n"
    for r in rows:
        md_content += f"| `{r['file']}` | **{r['status']}** | {r['size_mb']:.2f} MB | `{r['sha256']}` | {r['gzip_ok']} |\n"
        
    md_content += "\n## Verdict\n"
    if all_ok:
        md_content += "> [!NOTE]\n> All 9 target files downloaded successfully with valid Gzip checksums and no truncation.\n"
    else:
        md_content += "> [!WARNING]\n> One or more files are missing, truncated, or corrupt. Acquisition needs attention.\n"
        
    with open(os.path.join(OUT_DIR, "download_integrity.md"), "w") as f:
        f.write(md_content)
        
    return all_ok

def audit_dataset_and_tree():
    print("--- Auditing Retained Dataset & Process Trees ---")
    if not os.path.exists(PARSED_CSV):
        print(f"Parsed CSV not found: {PARSED_CSV}")
        return
        
    # Read only required columns to save memory
    cols = ['host', 'log_type', 'process_id', 'parent_process_id', 'process_guid', 'parent_process_guid', 'event_code', 'event_id']
    df = pd.read_csv(PARSED_CSV, usecols=cols, low_memory=False)
    
    total_events = len(df)
    unique_hosts = df['host'].nunique()
    events_per_host = df['host'].value_counts().to_dict()
    log_types = df['log_type'].value_counts().to_dict()
    
    # Process events (PROCESS and THREAD)
    proc_events = df[df['log_type'].isin(['PROCESS', 'THREAD'])]
    total_proc = len(proc_events)
    
    # PID/PPID coverage
    pid_coverage = proc_events['process_id'].notna().mean() * 100
    ppid_coverage = proc_events['parent_process_id'].notna().mean() * 100
    
    # Duplicate checks
    dup_event_ids = df['event_id'].duplicated().sum()
    
    # Check process GUID relationships (UUID mapping)
    proc_create = df[df['event_code'] == 'PROCESS:CREATE']
    total_proc_create = len(proc_create)
    
    # Map process_guid -> host to detect cross-host edges
    # Fast dict mapping using zip on non-null values
    valid_guids_df = df[df['process_guid'].notna()]
    guid_host_map = dict(zip(valid_guids_df['process_guid'], valid_guids_df['host']))
            
    # Fast zip-based check instead of iterrows()
    parent_guids = proc_create['parent_process_guid'].values
    hosts = proc_create['host'].values
    
    resolved_parents = 0
    cross_host_edges = 0
    orphan_count = 0
    
    for p_guid, h in zip(parent_guids, hosts):
        if pd.notna(p_guid) and p_guid != "":
            parent_host = guid_host_map.get(p_guid)
            if parent_host is not None:
                resolved_parents += 1
                if parent_host != h:
                    cross_host_edges += 1
            else:
                orphan_count += 1
        else:
            orphan_count += 1
            
    orphan_rate = (orphan_count / total_proc_create * 100) if total_proc_create > 0 else 0.0
    
    # Duplicate process relations
    dup_proc_relations = proc_create.duplicated(subset=['process_guid', 'parent_process_guid']).sum()
    
    # Print metrics
    print(f"Total events: {total_events}")
    print(f"Unique hosts: {unique_hosts}")
    print(f"Log type distribution: {log_types}")
    print(f"PID coverage: {pid_coverage:.2f}% | PPID coverage: {ppid_coverage:.2f}%")
    print(f"Duplicate event IDs: {dup_event_ids}")
    print(f"Process tree resolution: {resolved_parents} resolved, {orphan_count} orphans (Orphan rate: {orphan_rate:.2f}%)")
    print(f"Cross-host edges: {cross_host_edges}")
    print(f"Duplicate process relations: {dup_proc_relations}")
    
    return {
        "total_events": total_events,
        "unique_hosts": unique_hosts,
        "events_per_host": events_per_host,
        "log_types": log_types,
        "total_proc": total_proc,
        "pid_coverage": pid_coverage,
        "ppid_coverage": ppid_coverage,
        "dup_event_ids": dup_event_ids,
        "resolved_parents": resolved_parents,
        "orphan_count": orphan_count,
        "orphan_rate": orphan_rate,
        "cross_host_edges": cross_host_edges,
        "dup_proc_relations": dup_proc_relations
    }

def audit_labels(df_metrics):
    print("--- Auditing Labels ---")
    
    # Read the CSV file in chunks and filter labeled events to minimize memory
    labeled_chunks = []
    chunk_size = 500000
    for chunk in pd.read_csv(PARSED_CSV, chunksize=chunk_size, low_memory=False):
        labeled_chunk = chunk[chunk['technique_id'].notna()]
        labeled_chunks.append(labeled_chunk)
        
    labeled_events = pd.concat(labeled_chunks, ignore_index=True)
    print(f"Labeled events to audit: {len(labeled_events)}")
    
    audit_rows = []
    
    # Ground Truth PDF Narrative References
    # Day 1: 09/23/2019
    # Attack window: 15:20:00 UTC to 20:00:00 UTC
    d1_start = datetime.fromisoformat("2019-09-23T15:20:00+00:00")
    d1_end = datetime.fromisoformat("2019-09-23T20:00:00+00:00")
    
    n_high = 0
    n_medium = 0
    n_low = 0
    n_unsupported = 0
    
    for idx, row in labeled_events.iterrows():
        eid = row['event_id']
        host = str(row['host']).lower().split(".")[0]
        ts_str = row['timestamp']
        tech_id = row['technique_id']
        cmdline = str(row['command_line']) if pd.notna(row['command_line']) else ""
        img = str(row['image']) if pd.notna(row['image']) else ""
        rp = str(row['registry_path']) if pd.notna(row['registry_path']) else ""
        fp = str(row['file_path']) if pd.notna(row['file_path']) else ""
        log_type = row['log_type']
        event_code = row['event_code']
        
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            in_d1_window = (d1_start <= dt <= d1_end)
        except:
            dt = None
            in_d1_window = False
            
        confidence = "UNSUPPORTED"
        gt_evidence = ""
        rationale = ""
        action = ""
        
        # Audit criteria
        if in_d1_window:
            if host == "sysclient0201":
                if tech_id == "T1059.001" and "powershell" in img.lower() and ("runme" in cmdline.lower() or "news.com" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 11:23:29 console download of runme.bat and check-in"
                    action = "PowerShell Empire stager download and check-in"
                    rationale = f"Exact powershell stager cmdline match inside Day 1 window."
                elif tech_id == "T1112" and "windir" in rp.lower() and "environment" in rp.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 11:26:02 bypass UAC via Environment windir key modification"
                    action = "UAC Bypass Registry Modify"
                    rationale = "Exact Environment windir registry write inside Day 1 window."
                elif tech_id == "T1003.001" and "lsass" in img.lower() and event_code == "PROCESS:OPEN":
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 11:33:14 ran Mimikatz to collect passwords in memory"
                    action = "Mimikatz LSASS access"
                    rationale = "Process open targeting lsass.exe inside Day 1 window."
                elif tech_id == "T1112" and ("currentversion\\debug" in rp.lower() or "run" in rp.lower()) and event_code == "REGISTRY:SET":
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 11:39:25 established persistence by modifying Debug/Run registry entry"
                    action = "Persistence Registry Write"
                    rationale = "Registry persistence key modification inside Day 1 window."
                elif tech_id == "T1016" and ("ping" in img.lower() or "arp" in img.lower() or "ping" in cmdline.lower() or "arp" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 12:58:20 ARP scan, 13:15:48 ping sweep"
                    action = "Network Discovery ping/arp sweep"
                    rationale = "Ping or arp scan command invocation inside Day 1 window."
                elif tech_id == "T1047" and ("wmic" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:24:36 pivoted to Sysclient0402 using invoke_wmi"
                    action = "WMI lateral pivot invocation"
                    rationale = "Wmic process creation inside Day 1 window."
                elif tech_id == "T1113" and ("screenshot" in cmdline.lower() or log_type == "FILE" and "screenshot" in fp.lower()):
                    confidence = "MEDIUM_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 12:51:59 screenshot collection via Empire module"
                    action = "Desktop Screenshot Collection"
                    rationale = "Screenshot activity detected on host inside Day 1 window."
                    
            elif host == "sysclient0402":
                if tech_id == "T1047" and ("powershell" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:25:41 checked in as elevated agent via WMI pivot"
                    action = "WMI pivot target agent execution"
                    rationale = "Powershell execution inside WMI pivot check-in window."
                elif tech_id == "T1016" and "ping" in img.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:29:47 imported and ran ping sweep script"
                    action = "Ping sweep network discovery"
                    rationale = "Ping process creation on target inside Day 1 window."
                elif tech_id == "T1047" and ("wmic" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:35:22 pivoted to Sysclient0660 using invoke_wmi"
                    action = "WMI lateral pivot invocation"
                    rationale = "Wmic process creation on host inside Day 1 window."
                    
            elif host == "sysclient0660":
                if tech_id == "T1047" and ("powershell" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:35:22 checked in via WMI pivot"
                    action = "WMI pivot target agent check-in"
                    rationale = "Powershell execution inside WMI pivot check-in window."
                elif tech_id == "T1016" and "ipconfig" in img.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:38:31 ipconfig to obtain IP"
                    action = "Local IP configuration discovery"
                    rationale = "Ipconfig process creation inside discovery window."
                elif tech_id == "T1003.001" and "lsass" in img.lower() and event_code == "PROCESS:OPEN":
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:40:38 ran Mimikatz to obtain passwords"
                    action = "Mimikatz LSASS access"
                    rationale = "Process open targeting lsass.exe inside Day 1 window."
                elif tech_id == "T1087.002" and "powershell" in img.lower() and ("dc" in cmdline.lower() or "domain" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 13:54:11 script to return domain controller info"
                    action = "Domain Controller Enumeration"
                    rationale = "Powershell querying domain admin or controller info."
                elif tech_id == "T1105" and "zipfldr.dll" in fp.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:02:12 downloaded file zipfldr.dll"
                    action = "File download of zipfldr.dll stager"
                    rationale = "File create of dll inside download window."
                elif tech_id == "T1047" and ("wmic" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:04:45 pivoted to DC1 using invoke_wmi"
                    action = "WMI lateral pivot invocation to DC1"
                    rationale = "Wmic process creation targeting DC1."
                    
            elif host == "dc1":
                if tech_id == "T1047" and "powershell" in img.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:04:45 checked in via WMI pivot"
                    action = "WMI pivot target agent check-in"
                    rationale = "Powershell execution inside DC check-in window."
                elif tech_id == "T1003.001" and "lsass" in img.lower() and event_code == "PROCESS:OPEN":
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:07:21 ran Mimikatz"
                    action = "Mimikatz LSASS access"
                    rationale = "Process open targeting lsass.exe on DC."
                elif tech_id == "T1003.003" and ("lsadump" in cmdline.lower() or "sekurlsa" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:09:21 gathered hashes using Mimikatz lsadump"
                    action = "Mimikatz lsadump execution"
                    rationale = "Lsadump command arguments matched on DC."
                elif tech_id == "T1047" and ("wmic" in img.lower() or "wmic" in cmdline.lower()):
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = "PDF 09/23/19 14:45:13 pivoted to 14 workstations"
                    action = "WMI lateral pivot invocation to workstations"
                    rationale = "Wmic process creation spreading from DC to workstations."
                    
            elif host in {"sysclient0104", "sysclient0170", "sysclient0205", "sysclient0255", 
                          "sysclient0321", "sysclient0355", "sysclient0419", "sysclient0462", 
                          "sysclient0503", "sysclient0559", "sysclient0609", "sysclient0771", 
                          "sysclient0874", "sysclient0955"}:
                if tech_id == "T1059.001" and "powershell" in img.lower():
                    confidence = "HIGH_CONFIDENCE"
                    gt_evidence = f"PDF 09/23/19 14:45:13 pivoted from DC1 to {host.upper()}"
                    action = "Empire agent check-in on target workstation"
                    rationale = "Powershell check-in execution matching pivot stager check-in window."

        # Fallback signature checks if not matched in specific windows but contains blatant tools
        if confidence == "UNSUPPORTED":
            if "mimikatz" in cmdline.lower():
                confidence = "HIGH_CONFIDENCE"
                gt_evidence = "Mimikatz tool execution signature matched"
                action = "Mimikatz execution"
                rationale = "Mimikatz execution signature matched in command line."
            elif "lsadump" in cmdline.lower():
                confidence = "HIGH_CONFIDENCE"
                gt_evidence = "Lsadump tool execution signature matched"
                action = "Lsadump execution"
                rationale = "Lsadump command line signature matched."
            else:
                # General signatures like background powershell without stager context are unsupported!
                confidence = "UNSUPPORTED"
                gt_evidence = "No matching red-team action for host + timestamp window"
                action = "N/A"
                rationale = f"Generic background process '{img}' labeled without specific ground-truth context."

        if confidence == "HIGH_CONFIDENCE":
            n_high += 1
        elif confidence == "MEDIUM_CONFIDENCE":
            n_medium += 1
        elif confidence == "LOW_CONFIDENCE":
            n_low += 1
        else:
            n_unsupported += 1

        audit_rows.append({
            "event_id": eid,
            "host": host.upper(),
            "timestamp": ts_str,
            "log_type": log_type,
            "event_code": event_code,
            "command_line": cmdline,
            "technique_id": tech_id,
            "confidence_level": confidence,
            "ground_truth_evidence": gt_evidence,
            "rationale": rationale
        })

    audit_df = pd.DataFrame(audit_rows)
    audit_csv_path = os.path.join(OUT_DIR, "label_audit.csv")
    audit_df.to_csv(audit_csv_path, index=False)
    print(f"Saved label audit to {audit_csv_path}")
    print(f"Audited labels: {len(audit_df)} | HIGH: {n_high} | MEDIUM: {n_medium} | LOW: {n_low} | UNSUPPORTED: {n_unsupported}")
    
    # Write host_technique_matrix.csv
    # Matrix of Host vs Technique showing event count of HIGH_CONFIDENCE labels
    high_events = audit_df[audit_df["confidence_level"] == "HIGH_CONFIDENCE"]
    matrix_df = pd.crosstab(high_events["host"], high_events["technique_id"])
    matrix_csv_path = os.path.join(OUT_DIR, "host_technique_matrix.csv")
    matrix_df.to_csv(matrix_csv_path)
    print(f"Saved host technique matrix to {matrix_csv_path}")
    
    # Write label_audit.md
    md_content = "# OpTC Red-Team Label Audit Report\n\n"
    md_content += f"**Date/Time of Audit:** {datetime.now(timezone.utc).isoformat()}\n\n"
    md_content += f"Total labeled events audited: **{len(audit_df)}**\n"
    md_content += f"- **HIGH_CONFIDENCE**: {n_high}\n"
    md_content += f"- **MEDIUM_CONFIDENCE**: {n_medium}\n"
    md_content += f"- **LOW_CONFIDENCE**: {n_low}\n"
    md_content += f"- **UNSUPPORTED**: {n_unsupported}\n\n"
    
    md_content += "## Audit Verdict\n"
    if n_unsupported == 0 and n_high > 0:
        md_content += "> [!NOTE]\n> OPTC DATA READY FOR INTEGRATION. All labels mapped to ground-truth red-team activity are high confidence.\n"
    elif n_unsupported > 0:
        md_content += "> [!WARNING]\n> OPTC LABELING REQUIRES CORRECTION. Found unsupported background events erroneously labeled as attacks.\n"
    else:
        md_content += "> [!IMPORTANT]\n> No labels were verified. Labeling requires validation.\n"
        
    md_content += "\n## Sample Audited Labels (First 20)\n"
    md_content += "| Host | Timestamp | Log Type | Event Code | Technique | Confidence | Ground Truth / Rationale |\n"
    md_content += "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
    for idx, r in audit_df.head(20).iterrows():
        md_content += f"| {r['host']} | `{r['timestamp']}` | {r['log_type']} | `{r['event_code']}` | `{r['technique_id']}` | **{r['confidence_level']}** | {r['rationale']} |\n"
        
    with open(os.path.join(OUT_DIR, "label_audit.md"), "w") as f:
        f.write(md_content)
        
    # Write final_data_quality.md
    dq_content = "# OpTC Final Data Quality Assessment\n\n"
    dq_content += f"**Date/Time of Assessment:** {datetime.now(timezone.utc).isoformat()}\n\n"
    dq_content += "## 1. Dataset Scale & Diversity\n"
    dq_content += f"- **Total events retained:** {df_metrics['total_events']:,}\n"
    dq_content += f"- **Unique hosts:** {df_metrics['unique_hosts']}\n"
    dq_content += "- **Event count per host:**\n"
    for h, cnt in df_metrics['events_per_host'].items():
        dq_content += f"  - `{h}`: {cnt:,} events\n"
    dq_content += "\n## 2. Event Types & Format Representation\n"
    for lt, cnt in df_metrics['log_types'].items():
        dq_content += f"- **`{lt}`**: {cnt:,} events\n"
        
    dq_content += "\n## 3. Entity & Process Linkage\n"
    dq_content += f"- **PID Coverage:** {df_metrics['pid_coverage']:.2f}%\n"
    dq_content += f"- **PPID Coverage:** {df_metrics['ppid_coverage']:.2f}%\n"
    dq_content += f"- **Resolved parent-child process pairs:** {df_metrics['resolved_parents']:,}\n"
    dq_content += f"- **Process tree orphans:** {df_metrics['orphan_count']:,} ({df_metrics['orphan_rate']:.2f}% orphan rate)\n"
    dq_content += f"- **Cross-host process relations:** {df_metrics['cross_host_edges']} (must be 0)\n"
    dq_content += f"- **Duplicate event IDs:** {df_metrics['dup_event_ids']}\n"
    dq_content += f"- **Duplicate process relations:** {df_metrics['dup_proc_relations']}\n\n"
    
    dq_content += "## 4. Host-Technique Event Matrix (HIGH_CONFIDENCE only)\n"
    dq_content += "| Host | " + " | ".join(matrix_df.columns) + " |\n"
    dq_content += "| :--- | " + " | ".join([":---" for _ in matrix_df.columns]) + " |\n"
    for host_name, row_vals in matrix_df.iterrows():
        dq_content += f"| {host_name} | " + " | ".join([str(v) for v in row_vals]) + " |\n"
        
    dq_content += "\n## 5. Final Quality Verdict\n"
    if df_metrics['cross_host_edges'] == 0 and n_unsupported == 0 and n_high > 0:
        dq_content += "# OPTC DATA READY FOR INTEGRATION\n\n"
        dq_content += "> [!IMPORTANT]\n> Data quality validation PASSED. Process trees show zero cross-host boundary leaks, and all red-team attack labels are aligned with the official ground truth with high confidence.\n"
    else:
        dq_content += "# OPTC LABELING REQUIRES CORRECTION\n\n"
        dq_content += "> [!WARNING]\n> Data quality validation FAILED. Please review the issues reported above and execute corrections.\n"
        
    with open(os.path.join(OUT_DIR, "final_data_quality.md"), "w") as f:
        f.write(dq_content)
        
    print("Done generating all reports.")
    if df_metrics['cross_host_edges'] == 0 and n_unsupported == 0 and n_high > 0:
        print("FINAL VERDICT: OPTC DATA READY FOR INTEGRATION")
    else:
        print("FINAL VERDICT: OPTC LABELING REQUIRES CORRECTION")

def main():
    downloads_ok = audit_downloads()
    if not downloads_ok:
        print("Downloads validation failed. Cannot proceed with dataset audits.")
        return
        
    df_metrics = audit_dataset_and_tree()
    if df_metrics:
        audit_labels(df_metrics)

if __name__ == "__main__":
    main()
