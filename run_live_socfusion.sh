#!/bin/bash
# ============================================================
# SOCFusion GAT V2 Realtime Deployment Launcher
# ============================================================

echo "============================================================"
echo "⚡ STARTING SOCFUSION GAT V2 REALTIME DETECTION PIPELINE"
echo "============================================================"

# Set Python Path
export PYTHONPATH=.

# 1. Run Deployment Verification Check
echo "[1/2] Running GAT V2 Deployment Verification & Test Cycle..."
python3 src/deployment/live_inference_service.py

if [ $? -eq 0 ]; then
    echo "✓ Deployment verification passed successfully!"
else
    echo "❌ Deployment verification check failed."
    exit 1
fi

# 2. Launch Dashboard
echo "[2/2] Launching SOCFusion Interactive Dashboard on Port 8501..."
streamlit run src/app/app.py --server.port 8501
