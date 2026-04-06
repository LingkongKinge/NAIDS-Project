#!/bin/bash
echo "======================================"
echo "  NAIDS - Starting All Components"
echo "  Network Intrusion Detection System"
echo "  Linux Friends Association - 2026"
echo "======================================"
echo ""

# Clear old test alerts
echo "[] " > /home/lingkong/NAIDS_Project/api/alerts.json

# Start Flask API in background
echo "Starting Flask API..."
cd /home/lingkong/NAIDS_Project/api
python3 app.py &
API_PID=$!
echo "Flask API started (PID: $API_PID)"
sleep 2

# Open dashboard in browser
echo "Opening dashboard..."
firefox http://127.0.0.1:5500/dashboard/index.html &
sleep 2

echo ""
echo "======================================"
echo "  NAIDS System Ready!"
echo "  Dashboard: http://127.0.0.1:5500/dashboard/index.html"
echo "  API:       http://localhost:5000"
echo "======================================"
echo ""
echo "Starting capture engine (requires sudo)..."
sudo python3 /home/lingkong/NAIDS_Project/capture/capture_engine.py