import re
import datetime
from dateutil import parser as dt_parser

def normalize_timestamp(ts_str):
    if not ts_str:
        return ""
        
    ts_str = str(ts_str).strip()
    
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

tests = [
    "2022-02-09 12:02:20.969 +0000 UTC",
    "1658918559.957",
    "1658918561194",
    "10/09/2020 10:28:15 AM",
    "2021-03-24T21:49:22.619115200Z",
    "invalid string",
    "",
    "12/06/2021 10:17:14 PM"
]

for t in tests:
    print(f"'{t}' -> '{normalize_timestamp(t)}'")
