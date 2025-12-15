from flask import Flask, render_template, jsonify, request
import detector
import psutil
import datetime

import json
import os

app = Flask(__name__)

# File to store logs
LOG_FILE = 'detection_logs.json'

def load_logs():
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, 'r') as f:
                return json.load(f)
        except:
            return []
    return []

def save_logs(logs):
    with open(LOG_FILE, 'w') as f:
        json.dump(logs, f, indent=4)

# Load logs on startup
history_log = load_logs()
active_threats = set()

def add_log(event, details):
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    history_log.insert(0, {"time": timestamp, "event": event, "details": details}) # Newest first
    save_logs(history_log)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan')
def scan():
    threats = detector.scan_processes()
    
    # Log logic
    current_pids = set()
    for t in threats:
        pid = t['pid']
        current_pids.add(pid)
        if pid not in active_threats:
            add_log("Threat Detected", f"{t['name']} (PID: {pid})")
            active_threats.add(pid)
    
    # Check for removed threats
    removed_pids = active_threats - current_pids
    for pid in removed_pids:
        add_log("Threat Removed", f"PID: {pid} stopped")
        active_threats.remove(pid)

    status = "THREAT DETECTED" if threats else "SAFE"
    return jsonify({
        "status": status,
        "threats": threats,
        "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/logs')
def get_logs():
    return jsonify(history_log)

@app.route('/api/kill/<int:pid>', methods=['POST'])
def kill_process(pid):
    try:
        process = psutil.Process(pid)
        process.terminate()
        return jsonify({"success": True, "message": f"Process {pid} terminated."})
    except psutil.NoSuchProcess:
        return jsonify({"success": False, "message": "Process not found."}), 404
    except psutil.AccessDenied:
        return jsonify({"success": False, "message": "Access denied."}), 403
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
