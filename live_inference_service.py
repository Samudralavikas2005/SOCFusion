import os
import sys

# Ensure src/deployment is in path
script_dir = os.path.dirname(os.path.abspath(__file__))
deployment_dir = os.path.join(script_dir, "src", "deployment")
if deployment_dir not in sys.path:
    sys.path.insert(0, deployment_dir)
if script_dir not in sys.path:
    sys.path.insert(0, script_dir)

from live_inference_service import LiveInferenceService

if __name__ == "__main__":
    service = LiveInferenceService()
    service.run_inference_cycle()
