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
