/**
 * PacketPanther Dashboard JavaScript
 */

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('PacketPanther dashboard initialized');
    
    // Add active class to current nav item
    highlightCurrentNavItem();
    
    // Setup form submissions if they exist
    setupFormSubmissions();
});

// Highlight the current navigation item based on URL
function highlightCurrentNavItem() {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('nav ul li a');
    
    navLinks.forEach(link => {
        if ((currentPath === '/' && link.getAttribute('href') === '/') || 
            (currentPath !== '/' && link.getAttribute('href').includes(currentPath))) {
            link.parentElement.classList.add('active');
        }
    });
}

// Setup AJAX form submissions
function setupFormSubmissions() {
    // Traceroute form
    const traceForm = document.getElementById('trace-form');
    if (traceForm) {
        traceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const target = document.getElementById('trace-target').value;
            showLoadingIndicator('trace-results');
            
            // In a real app, this would be an AJAX call
            setTimeout(() => {
                displayMockTraceResults(target);
                hideLoadingIndicator('trace-results');
            }, 1500);
        });
    }
    
    // Port scan form
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('scan-host').value;
            const ports = document.getElementById('scan-ports').value;
            showLoadingIndicator('scan-results');
            
            // In a real app, this would be an AJAX call
            setTimeout(() => {
                displayMockScanResults(host, ports);
                hideLoadingIndicator('scan-results');
            }, 2000);
        });
    }
    
    // SNMP form
    const snmpForm = document.getElementById('snmp-form');
    if (snmpForm) {
        snmpForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const host = document.getElementById('snmp-host').value;
            const community = document.getElementById('snmp-community').value;
            showLoadingIndicator('snmp-results');
            
            // In a real app, this would be an AJAX call
            setTimeout(() => {
                displayMockSNMPResults(host, community);
                hideLoadingIndicator('snmp-results');
            }, 1800);
        });
    }
}

// Show loading indicator in a container
function showLoadingIndicator(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = '<div class="loading-indicator">Loading results...</div>';
    }
}

// Hide loading indicator and clear container
function hideLoadingIndicator(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        const loadingIndicator = container.querySelector('.loading-indicator');
        if (loadingIndicator) {
            loadingIndicator.remove();
        }
    }
}

// Display mock traceroute results
function displayMockTraceResults(target) {
    const resultsContainer = document.getElementById('trace-results');
    if (!resultsContainer) return;
    
    const hops = [
        { hop: 1, address: '192.168.1.1', hostname: 'router.local', latency: 1.2 },
        { hop: 2, address: '10.0.0.1', hostname: 'isp-gateway.net', latency: 5.8 },
        { hop: 3, address: '172.16.0.1', hostname: 'core1.isp.net', latency: 12.3 },
        { hop: 4, address: '172.16.0.254', hostname: 'border1.isp.net', latency: 15.7 },
        { hop: 5, address: '198.51.100.1', hostname: 'exchange-point.net', latency: 22.1 },
        { hop: 6, address: '203.0.113.1', hostname: 'ingress.target-network.com', latency: 28.4 },
        { hop: 7, address: '203.0.113.10', hostname: target, latency: 32.9 }
    ];
    
    let html = `
        <h3>Traceroute Results for ${target}</h3>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Hop</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Latency (ms)</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    hops.forEach(hop => {
        html += `
            <tr>
                <td>${hop.hop}</td>
                <td>${hop.address}</td>
                <td>${hop.hostname}</td>
                <td>${hop.latency.toFixed(1)} ms</td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    resultsContainer.innerHTML = html;
}

// Display mock port scan results
function displayMockScanResults(host, ports) {
    const resultsContainer = document.getElementById('scan-results');
    if (!resultsContainer) return;
    
    const openPorts = [22, 80, 443, 3389];
    const closedPorts = [21, 23, 25, 53, 110, 139, 445, 8080];
    
    let html = `
        <h3>Port Scan Results for ${host}</h3>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Port</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Latency (ms)</th>
                </tr>
            </thead>
            <tbody>
    `;
    
    // Add open ports to the table
    openPorts.forEach(port => {
        const service = getServiceName(port);
        html += `
            <tr>
                <td>${port}</td>
                <td><span class="badge success">Open</span></td>
                <td>${service}</td>
                <td>${(Math.random() * 10 + 1.5).toFixed(1)} ms</td>
            </tr>
        `;
    });
    
    // Add closed ports to the table
    closedPorts.forEach(port => {
        const service = getServiceName(port);
        html += `
            <tr>
                <td>${port}</td>
                <td><span class="badge danger">Closed</span></td>
                <td>${service}</td>
                <td>-</td>
            </tr>
        `;
    });
    
    html += `
            </tbody>
        </table>
    `;
    
    resultsContainer.innerHTML = html;
}

// Display mock SNMP results
function displayMockSNMPResults(host, community) {
    const resultsContainer = document.getElementById('snmp-results');
    if (!resultsContainer) return;
    
    const deviceInfo = {
        sysName: host,
        sysDescr: 'Network Device Running SNMPv2',
        sysUpTime: '45 days, 3 hours, 12 minutes',
        sysContact: 'admin@example.com',
        sysLocation: 'Server Room'
    };
    
    const interfaces = [
        { index: 1, name: 'GigabitEthernet0/1', description: 'WAN Connection', type: 'ethernet-csmacd', speed: '1 Gbps', adminStatus: 'up', operStatus: 'up', inOctets: '1.2 GB', outOctets: '3.5 GB' },
        { index: 2, name: 'GigabitEthernet0/2', description: 'LAN Connection', type: 'ethernet-csmacd', speed: '1 Gbps', adminStatus: 'up', operStatus: 'up', inOctets: '5.7 GB', outOctets: '2.1 GB' },
        { index: 3, name: 'GigabitEthernet0/3', description: 'DMZ Connection', type: 'ethernet-csmacd', speed: '1 Gbps', adminStatus: 'up', operStatus: 'up', inOctets: '342 MB', outOctets: '128 MB' },
        { index: 4, name: 'Loopback0', description: 'Management Interface', type: 'softwareLoopback', speed: '10 Mbps', adminStatus: 'up', operStatus: 'up', inOctets: '45 KB', outOctets: '62 KB' }
    ];
    
    let html = `
        <h3>SNMP Results for ${host}</h3>
        <div class="snmp-info">
            <h4>System Information</h4>
            <table class="results-table">
                <tr>
                    <th>System Name</th>
                    <td>${deviceInfo.sysName}</td>
                </tr>
                <tr>
                    <th>Description</th>
                    <td>${deviceInfo.sysDescr}</td>
                </tr>
                <tr>
                    <th>Uptime</th>
                    <td>${deviceInfo.sysUpTime}</td>
                </tr>
                <tr>
                    <th>Contact</th>
                    <td>${deviceInfo.sysContact}</td>
                </tr>
                <tr>
                    <th>Location</th>
                    <td>${deviceInfo.sysLocation}</td>
                </tr>
            </table>
        </div>
        
        <div class="snmp-interfaces">
            <h4>Interfaces</h4>
            <table class="results-table">
                <thead>
                    <tr>
                        <th>Index</th>
                        <th>Name</th>
                        <th>Description</th>
                        <th>Type</th>
                        <th>Speed</th>
                        <th>Status</th>
                        <th>In</th>
                        <th>Out</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    interfaces.forEach(iface => {
        html += `
            <tr>
                <td>${iface.index}</td>
                <td>${iface.name}</td>
                <td>${iface.description}</td>
                <td>${iface.type}</td>
                <td>${iface.speed}</td>
                <td>${iface.operStatus}</td>
                <td>${iface.inOctets}</td>
                <td>${iface.outOctets}</td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    resultsContainer.innerHTML = html;
}

// Get service name for a port
function getServiceName(port) {
    const services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        139: 'NetBIOS',
        443: 'HTTPS',
        445: 'SMB',
        3389: 'RDP',
        8080: 'HTTP-Alt'
    };
    
    return services[port] || 'Unknown';
}
