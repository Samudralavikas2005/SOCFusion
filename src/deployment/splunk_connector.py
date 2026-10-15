import os
import time
import json
import logging
import urllib3
import requests

# Disable insecure HTTPS warnings for self-signed certificates in lab VMs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class SplunkConnector:
    """
    Connects to Splunk REST API (Port 8089) in the VM lab network
    to poll Sysmon / Windows Event Log telemetry.
    """
    def __init__(self, host=None, port=8089, username=None, password=None, index="main"):
        if host is None:
            host = os.environ.get("SPLUNK_HOST", "127.0.0.1")
        if username is None:
            username = os.environ.get("SPLUNK_USER", os.environ.get("SPLUNK_USERNAME", "admin"))
        if password is None:
            password = os.environ.get("SPLUNK_PASSWORD", os.environ.get("SPLUNK_PASS", "Vikas@2005"))
            
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.index = index
        self.base_url = f"https://{self.host}:{self.port}"
        self.session = requests.Session()
        self.session.auth = (self.username, self.password)
        self.session.verify = False

    def test_connection(self):
        """Check if Splunk REST API is reachable."""
        try:
            res = self.session.get(f"{self.base_url}/services/server/info?output_mode=json", timeout=5)
            if res.status_code == 200:
                server_name = res.json()["entry"][0]["content"].get("serverName", "Unknown")
                logging.info(f"Connected to Splunk Server '{server_name}' at {self.host}:{self.port}")
                return True
            else:
                logging.warning(f"Splunk API returned status code: {res.status_code}")
                return False
        except Exception as e:
            logging.warning(f"Could not connect to Splunk API at {self.base_url}: {e}")
            return False

    def fetch_recent_sysmon_events(self, earliest_time="-15m", search_query=None):
        """
        Query Splunk for recent Sysmon events.
        """
        if not search_query:
            search_query = f"search index={self.index} (sourcetype=*sysmon* OR EventCode=1 OR EventCode=3 OR EventCode=7 OR EventCode=11) | sort - _time | head 500"
        
        try:
            # Create search job
            search_job_url = f"{self.base_url}/services/search/jobs"
            data = {
                "search": search_query,
                "earliest_time": earliest_time,
                "exec_mode": "oneshot",
                "output_mode": "json"
            }
            res = self.session.post(search_job_url, data=data, timeout=15)
            if res.status_code == 200:
                results = res.json().get("results", [])
                logging.info(f"Fetched {len(results)} events from Splunk index '{self.index}'")
                return results
            else:
                logging.error(f"Splunk search failed: {res.text}")
                return []
        except Exception as e:
            logging.error(f"Error fetching logs from Splunk: {e}")
            return []

if __name__ == "__main__":
    connector = SplunkConnector()
    print("Testing Splunk REST API Connection...")
    status = connector.test_connection()
    print(f"Splunk REST API Connection Status: {'SUCCESS' if status else 'OFFLINE (Mock/Fallback Mode Available)'}")
