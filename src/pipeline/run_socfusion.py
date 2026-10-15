import os
import subprocess
import sys

def run_script(script_path):
    print(f"\n{'='*50}\nExecuting: {script_path}\n{'='*50}")
    result = subprocess.run([sys.executable, script_path], cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
    if result.returncode != 0:
        print(f"FAILED: {script_path}")
        sys.exit(1)
    print(f"SUCCESS: {script_path}")

def main():
    print("SOCFusion End-to-End Pipeline Execution")
    
    scripts = [
        "src/data/features_v3/build_features_v3.py",
        "src/data/graph_construction_v4.py",
        "src/analysis/inference_validation.py",
        "src/attack_chain/reconstruct_chains.py",
        "src/mitre/mapper.py",
        "src/analysis/gap_analysis.py"
    ]
    
    for script in scripts:
        run_script(script)
        
    print("\nSOCFusion Pipeline Complete. Ready for Deployment.")

if __name__ == "__main__":
    main()
