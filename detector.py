import psutil
import time

def scan_processes():
    suspicious_processes = []
    
    # List of signatures to look for
    signatures = [
        "keylogger.py",
        "keylogger.sh",
        "keylog",
        "hook"
    ]

    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pinfo = proc.info
                cmdline = pinfo['cmdline']
                
                if cmdline:
                    # Join cmdline list to string for easier searching
                    cmd_str = " ".join(cmdline).lower()
                    
                    for sig in signatures:
                        if sig in cmd_str:
                            # Avoid detecting the detector itself or the server
                            if "detector.py" in cmd_str or "server.py" in cmd_str:
                                continue
                                
                            suspicious_processes.append({
                                "pid": pinfo['pid'],
                                "name": pinfo['name'],
                                "cmdline": cmd_str,
                                "status": "running"
                            })
                            break # Stop checking signatures for this process once found
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    except Exception as e:
        print(f"Error scanning processes: {e}")

    return suspicious_processes

if __name__ == "__main__":
    # Test run
    threats = scan_processes()
    if threats:
        print("Threats detected:", threats)
    else:
        print("System safe.")
