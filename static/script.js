document.addEventListener('DOMContentLoaded', () => {
    const statusCard = document.getElementById('status-card');
    const statusIcon = document.getElementById('status-icon-i');
    const systemStatus = document.getElementById('system-status');
    const statusDesc = document.getElementById('status-desc');
    const lastScan = document.getElementById('last-scan');
    const threatList = document.getElementById('threat-list');
    const noThreats = document.getElementById('no-threats');


    async function scan() {
        try {
            const response = await fetch('/api/scan');
            const data = await response.json();

            lastScan.textContent = data.scan_time;

            if (data.status === 'THREAT DETECTED') {
                // Update Status Card
                statusCard.classList.add('danger');
                statusIcon.className = 'fas fa-exclamation-triangle';
                systemStatus.textContent = 'Threat Detected';
                statusDesc.textContent = `${data.threats.length} suspicious process(es) identified. Action required.`;
                
                // Update Threat List
                if (noThreats) noThreats.style.display = 'none';
                
                // Clear existing list
                threatList.innerHTML = ''; 
                
                data.threats.forEach(threat => {
                    const card = document.createElement('div');
                    card.className = 'threat-card';
                    
                    card.innerHTML = `
                        <div class="threat-header">
                            <span class="threat-name">${threat.name}</span>
                            <span class="threat-pid">PID: ${threat.pid}</span>
                        </div>
                        <div class="threat-path expanded">
                            <i class="fas fa-folder-open"></i> ${threat.cmdline}
                        </div>
                        
                        <div class="remediation-steps">
                            <div class="remediation-title"><i class="fas fa-info-circle"></i> Manual Removal Required</div>
                            <div class="remediation-item">
                                <span class="label">Task Manager:</span> End process with PID <strong>${threat.pid}</strong>
                            </div>
                            <div class="remediation-item">
                                <span class="label">Command Line:</span> 
                                <div class="code-wrapper">
                                    <code>taskkill /F /PID ${threat.pid}</code>
                                    <button class="btn-copy" onclick="copyCommand('taskkill /F /PID ${threat.pid}', this)">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </div>
                            </div>
                        </div>
                    `;

                    threatList.appendChild(card);
                });

            } else {
                // Safe State
                statusCard.classList.remove('danger');
                statusIcon.className = 'fas fa-check-circle';
                systemStatus.textContent = 'System Secure';
                statusDesc.textContent = 'No active threats detected on your system.';
                
                threatList.innerHTML = '';
                threatList.appendChild(noThreats);
                noThreats.style.display = 'block';
            }

        } catch (error) {
            console.error('Error fetching scan data:', error);
        }
    }
    
    // Expose copy function
    window.copyCommand = function(text, btn) {
        navigator.clipboard.writeText(text).then(() => {
            const originalIcon = btn.innerHTML;
            btn.innerHTML = '<i class="fas fa-check"></i>';
            btn.classList.add('copied');
            
            setTimeout(() => {
                btn.innerHTML = originalIcon;
                btn.classList.remove('copied');
            }, 2000);
            
            addLog('Action', 'Copied kill command to clipboard');
        }).catch(err => {
            console.error('Failed to copy:', err);
            addLog('Error', 'Failed to copy command');
        });
    };

    // Expose killProcess to global scope
    // Expose killProcess to global scope
    window.killProcess = async function(pid) {
        // Removed blocking confirm for better UX/reliability
        // if (!confirm(`Are you sure you want to terminate process ${pid}?`)) return;
        
        addLog('Action', `Attempting to terminate PID ${pid}...`);
        
        try {
            const response = await fetch(`/api/kill/${pid}`, { method: 'POST' });
            const result = await response.json();
            
            if (result.success) {
                // alert('Process terminated successfully.'); // Removed alert
                addLog('Success', `Process ${pid} terminated.`);
                scan(); // Refresh immediately
            } else {
                // alert(`Failed to terminate: ${result.message}`); // Removed alert
                addLog('Error', `Failed to terminate PID ${pid}: ${result.message}`);
            }
        } catch (error) {
            console.error(error);
            addLog('Error', `Network error terminating PID ${pid}`);
        }
    };

    // Navigation Logic
    const navDashboard = document.getElementById('nav-dashboard');
    const navLogs = document.getElementById('nav-logs');
    
    const viewDashboard = document.getElementById('view-dashboard');
    const viewLogs = document.getElementById('view-logs');
    const pageTitle = document.getElementById('page-title');

    function switchView(viewName) {
        // Reset Nav
        navDashboard.classList.remove('active');
        navLogs.classList.remove('active');

        // Hide Views
        viewDashboard.classList.add('hidden');
        viewLogs.classList.add('hidden');

        // Activate Selected
        if (viewName === 'dashboard') {
            navDashboard.classList.add('active');
            viewDashboard.classList.remove('hidden');
            pageTitle.textContent = 'System Overview';
        } else if (viewName === 'logs') {
            navLogs.classList.add('active');
            viewLogs.classList.remove('hidden');
            pageTitle.textContent = 'Activity Logs';
            fetchLogs(); // Fetch latest logs
        }
    }

    navDashboard.addEventListener('click', (e) => { e.preventDefault(); switchView('dashboard'); });
    navLogs.addEventListener('click', (e) => { e.preventDefault(); switchView('logs'); });

    // Logger
    const logTableBody = document.getElementById('log-table-body');
    
    async function fetchLogs() {
        try {
            const response = await fetch('/api/logs');
            const logs = await response.json();
            
            logTableBody.innerHTML = '';
            
            if (logs.length === 0) {
                logTableBody.innerHTML = '<tr><td colspan="3" style="text-align:center; color:var(--text-secondary);">No logs available</td></tr>';
                return;
            }

            logs.forEach(log => {
                const row = document.createElement('tr');
                row.innerHTML = `<td>${log.time}</td><td>${log.event}</td><td>${log.details}</td>`;
                logTableBody.appendChild(row);
            });
        } catch (error) {
            console.error('Error fetching logs:', error);
        }
    }

    // Add local log (for client-side actions like copy)
    function addLog(event, details) {
        // We can still add local logs visually or send them to backend if needed.
        // For now, let's just append to the table if it's visible, but rely on backend for persistence.
        // Actually, let's just rely on fetching logs for system events.
        // For client actions like "Copied", we can just show a toast or ignore logging them persistently for now as user asked for "past key logger detection logs".
        // But to keep the "Copied" feedback, let's just keep a simple append for now, but it won't persist.
        const row = document.createElement('tr');
        const time = new Date().toLocaleTimeString();
        row.innerHTML = `<td>${time}</td><td>${event}</td><td>${details}</td>`;
        if (logTableBody.children[0] && logTableBody.children[0].children.length === 1) {
            logTableBody.innerHTML = '';
        }
        logTableBody.prepend(row);
    }
    
    // Hook into scan for logging
    let lastStatus = 'SAFE';
    const originalScan = scan; // Keep reference if needed, but we are inside the closure so we can just modify the logic inside scan() or wrap it.
    // Actually, let's just modify the scan function logic slightly by checking state changes.
    // Since I can't easily wrap the existing scan function without rewriting it all in this tool, 
    // I will rely on the fact that I'm appending this code. 
    // Wait, I am replacing the end of the file. I should probably rewrite the scan function or add the logging logic there.
    // But the user asked to "continue" and I am replacing the end. 
    // Let's just leave the logging for manual actions for now to avoid breaking the scan loop which is defined above.

    // Poll every 5 seconds
    setInterval(scan, 5000);
    scan(); // Initial call
});
