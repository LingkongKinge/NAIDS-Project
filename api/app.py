from flask import Flask, jsonify
from flask_cors import CORS
import json
import os
import psutil
import datetime

app = Flask(__name__)
CORS(app)  # Allow dashboard to access this API

# Path to our alert log file
ALERTS_FILE = '/home/lingkong/NAIDS_Project/api/alerts.json'

def read_alerts():
    """Read all alerts from the JSON file"""
    try:
        with open(ALERTS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

# ─── ROUTE 1: Get All Alerts ─────────────────────────────────
@app.route('/alerts', methods=['GET'])
def get_alerts():
    """Returns all detected alerts"""
    alerts = read_alerts()
    return jsonify({
        'status': 'success',
        'total': len(alerts),
        'alerts': alerts
    })

# ─── ROUTE 2: Get Summary Statistics ─────────────────────────
@app.route('/stats', methods=['GET'])
def get_stats():
    """Returns summary statistics for the dashboard"""
    alerts = read_alerts()

    # Count each attack type
    attack_counts = {}
    for alert in alerts:
        attack_type = alert.get('type', 'Unknown')
        attack_counts[attack_type] = attack_counts.get(attack_type, 0) + 1

    # Get recent alerts (last 10)
    recent = alerts[-10:] if len(alerts) > 10 else alerts

    return jsonify({
        'status': 'success',
        'total_alerts': len(alerts),
        'attack_counts': attack_counts,
        'recent_alerts': recent,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

# ─── ROUTE 3: Get System Status ──────────────────────────────
@app.route('/status', methods=['GET'])
def get_status():
    """Returns system health information"""
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')

    return jsonify({
        'status': 'online',
        'cpu_percent': cpu,
        'memory_percent': memory.percent,
        'memory_used_gb': round(memory.used / (1024**3), 2),
        'memory_total_gb': round(memory.total / (1024**3), 2),
        'disk_percent': disk.percent,
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

# ─── ROUTE 4: Clear All Alerts ───────────────────────────────
@app.route('/clear', methods=['GET'])
def clear_alerts():
    """Clears all alerts from the log"""
    with open(ALERTS_FILE, 'w') as f:
        json.dump([], f)
    return jsonify({
        'status': 'success',
        'message': 'All alerts cleared'
    })

# ─── ROUTE 5: Health Check ───────────────────────────────────
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'system': 'NAIDS - Network Anomaly and Intrusion Detection System',
        'version': '1.0',
        'status': 'running',
        'routes': ['/alerts', '/stats', '/status', '/clear']
    })

if __name__ == '__main__':
    print("=== NAIDS Flask API Starting ===")
    print("API running at: http://localhost:5000")
    print("Available routes:")
    print("  http://localhost:5000/         - System info")
    print("  http://localhost:5000/alerts   - All alerts")
    print("  http://localhost:5000/stats    - Statistics")
    print("  http://localhost:5000/status   - System health")
    print("  http://localhost:5000/clear    - Clear alerts")
    app.run(host='0.0.0.0', port=5000, debug=False)