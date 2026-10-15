import pandas as pd
import os

out_dir = "/home/vikas/SOCFusion/data/analysis/optc_selective"
raw_labels_file = os.path.join(out_dir, "label_audit_raw.csv")

if not os.path.exists(raw_labels_file):
    print("Waiting for raw labels file")
    exit(1)

df = pd.read_csv(raw_labels_file)
df = df.fillna("")

ground_truth = {
    "SysClient0201.systemia.com": True,
    "SysClient0402.systemia.com": True,
    "SysClient0660.systemia.com": True,
    "DC1.systemia.com": True,
    "SysClient0501.systemia.com": True,
    "SysClient0811.systemia.com": True,
    "SysClient0005.systemia.com": True,
    "SysClient0051.systemia.com": True,
    "SysClient0351.systemia.com": True,
    "SysClient0010.systemia.com": True,
    "SysClient0069.systemia.com": True,
    "SysClient0203.systemia.com": True,
    "SysClient0358.systemia.com": True,
    "SysClient0618.systemia.com": True,
    "SysClient0851.systemia.com": True,
    "SysClient0974.systemia.com": True,
    "SysClient0104.systemia.com": True,
    "SysClient0170.systemia.com": True,
    "SysClient0205.systemia.com": True,
    "SysClient0255.systemia.com": True,
    "SysClient0321.systemia.com": True,
    "SysClient0355.systemia.com": True,
    "SysClient0419.systemia.com": True,
    "SysClient0462.systemia.com": True,
    "SysClient0503.systemia.com": True,
    "SysClient0559.systemia.com": True,
    "SysClient0609.systemia.com": True,
    "SysClient0771.systemia.com": True,
    "SysClient0874.systemia.com": True,
    "SysClient0955.systemia.com": True
}

def is_ground_truth_supported(host, cmdline, procname):
    host_lower = host.lower()
    cmd_lower = cmdline.lower()
    proc_lower = procname.lower()
    
    matched_host = False
    for gt_host in ground_truth.keys():
        if gt_host.lower() == host_lower:
            matched_host = True
            break
            
    if not matched_host:
        return "UNSUPPORTED", "Host not in Red Team activity"
        
    if "mimikatz" in proc_lower or "mimikatz" in cmd_lower or "lsadump" in cmd_lower:
        return "HIGH_CONFIDENCE", "Mimikatz signature matches Red Team"
    if "wmi" in proc_lower or "wmiprvse" in proc_lower:
        return "HIGH_CONFIDENCE", "WMI lateral movement signature matches Red Team"
    if "reg" in proc_lower and ("debug" in cmd_lower or "run" in cmd_lower):
        return "HIGH_CONFIDENCE", "Registry persistence matches Red Team"
    if "ping" in proc_lower or "arp" in proc_lower:
        return "HIGH_CONFIDENCE", "Discovery/Scan matches Red Team"
    if "filetransfer1000" in cmd_lower or "movingonup" in cmd_lower or "nc.exe" in cmd_lower:
        return "HIGH_CONFIDENCE", "Netcat exfil matches Red Team"
    if "plink" in proc_lower or "plink" in cmd_lower:
        return "HIGH_CONFIDENCE", "Plink tunnel matches Red Team"
    if "winword" in proc_lower:
        return "HIGH_CONFIDENCE", "Phishing doc matches Red Team"
    if "update.exe" in proc_lower or "update.exe" in cmd_lower:
        return "HIGH_CONFIDENCE", "Malicious update matches Red Team"

    if "powershell" in proc_lower or "powershell" in cmd_lower:
        # Check if it's generic powershell. Ground truth says powershell empire was heavily used.
        return "MEDIUM_CONFIDENCE", "Powershell execution on compromised host"
        
    if "cmd" in proc_lower or "ipconfig" in proc_lower or "net" in proc_lower:
        return "LOW_CONFIDENCE", "Generic discovery command on compromised host"
        
    return "UNSUPPORTED", "Process not explicitly mapped to Red Team activity"

results = []
conf_counts = {"HIGH_CONFIDENCE": 0, "MEDIUM_CONFIDENCE": 0, "LOW_CONFIDENCE": 0, "UNSUPPORTED": 0}

for idx, row in df.iterrows():
    host = row['host']
    tech = row['technique_id']
    cmd = row['command_line']
    proc = row['process_name']
    ev_id = row['source_event']
    ts = row['timestamp']
    
    conf, reason = is_ground_truth_supported(host, cmd, proc)
    conf_counts[conf] += 1
    
    results.append({
        'technique_id': tech,
        'host': host,
        'timestamp': ts,
        'process_name': proc,
        'command_line': cmd,
        'source_event': ev_id,
        'confidence': conf,
        'reason': reason
    })

res_df = pd.DataFrame(results)
res_df.to_csv(os.path.join(out_dir, "label_audit.csv"), index=False)

matrix = pd.crosstab(res_df['host'], res_df['technique_id'])
matrix.to_csv(os.path.join(out_dir, "host_technique_matrix.csv"))

md = f"""# Label Audit Summary

Total Labels Evaluated: {len(res_df)}

## Confidence Distribution
- HIGH_CONFIDENCE: {conf_counts['HIGH_CONFIDENCE']}
- MEDIUM_CONFIDENCE: {conf_counts['MEDIUM_CONFIDENCE']}
- LOW_CONFIDENCE: {conf_counts['LOW_CONFIDENCE']}
- UNSUPPORTED: {conf_counts['UNSUPPORTED']}

## Unsupported Label Examples
"""
if "UNSUPPORTED" in res_df['confidence'].values:
    samples = res_df[res_df['confidence'] == 'UNSUPPORTED'].head(20)
    for _, r in samples.iterrows():
        md += f"- **{r['technique_id']}** on {r['host']}: Process `{r['process_name']}` Cmd: `{r['command_line']}`\n"

with open(os.path.join(out_dir, "label_audit.md"), "w") as f:
    f.write(md)

# Generate final data quality report based on stats and labels
with open(os.path.join(out_dir, "stats_temp.md"), "r") as f:
    stats = f.read()

quality_md = f"""# OpTC Final Data Quality Report

{stats}

## Label Quality
- HIGH_CONFIDENCE: {conf_counts['HIGH_CONFIDENCE']}
- MEDIUM_CONFIDENCE: {conf_counts['MEDIUM_CONFIDENCE']}
- LOW_CONFIDENCE: {conf_counts['LOW_CONFIDENCE']}
- UNSUPPORTED: {conf_counts['UNSUPPORTED']}

## Conclusion
"""

if conf_counts['UNSUPPORTED'] > (len(res_df) * 0.1):
    quality_md += "\n**OPTC LABELING REQUIRES CORRECTION**\n\nToo many labels lack red-team ground truth support or occur on benign hosts."
else:
    quality_md += "\n**OPTC DATA READY FOR INTEGRATION**\n"

with open(os.path.join(out_dir, "final_data_quality.md"), "w") as f:
    f.write(quality_md)

print("Label evaluation complete.")
