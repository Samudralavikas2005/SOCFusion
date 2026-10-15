import json
from src.data.normalize import create_empty_event, normalize_timestamp

class JSONParser:
    def parse(self, filepath, technique_id, scenario, rel_path):
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            for line_no, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                yield self._process_event(line, filepath, line_no, technique_id, scenario, rel_path)

    def _process_event(self, raw_event, filepath, line_no, technique_id, scenario, rel_path):
        event = create_empty_event()
        event['raw_event'] = raw_event
        event['technique_id'] = technique_id
        event['scenario'] = scenario
        event['source_file'] = rel_path
        
        try:
            data = json.loads(raw_event)
            
            orig_ts = ''
            for key in ['EventTime', 'UtcTime', 'device_timestamp', 'ContextTimeStamp', 'timestamp']:
                val = data.get(key)
                if val is not None and str(val).strip() != '':
                    orig_ts = str(val)
                    break
                    
            event['original_timestamp'] = orig_ts
            event['timestamp'] = normalize_timestamp(orig_ts)
            
            event['event_code'] = str(data.get('EventID', ''))
            event['host'] = data.get('Hostname', data.get('Computer', ''))
            event['source'] = data.get('SourceName', '')
            event['log_type'] = data.get('Channel', 'json_log')
            event['user'] = data.get('AccountName', data.get('SubjectUserName', ''))
            event['process_id'] = str(data.get('ProcessID', data.get('ProcessId', '')))
            event['src_ip'] = data.get('IpAddress', data.get('SourceIp', ''))
            event['src_port'] = str(data.get('IpPort', data.get('SourcePort', '')))
            event['raw_message'] = data.get('Message', '')
            event['logon_id'] = str(data.get('SubjectLogonId', ''))
            event['logon_type'] = str(data.get('LogonType', ''))
            event['process_name'] = data.get('ProcessName', '')
        except Exception as e:
            return {'error': str(e), 'line_no': line_no, 'source_file': filepath, 'raw_event': raw_event}
        
        return event
