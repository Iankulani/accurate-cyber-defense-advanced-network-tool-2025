#!/usr/bin/env python3
"""
Cybersecurity Vulnerability Scanning and Defense Tool
A comprehensive network security monitoring tool with GUI interface
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import subprocess
import time
import psutil
import json
import datetime
import re
import queue
import ipaddress
from collections import defaultdict, deque
import platform
import os

class NetworkMonitor:
    """Network monitoring and threat detection engine"""
    
    def __init__(self):
        self.is_monitoring = False
        self.port_scan_threshold = 10  # ports scanned per second
        self.connection_threshold = 100  # connections per minute
        self.traffic_baseline = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        self.connection_log = defaultdict(list)
        self.port_scan_log = defaultdict(list)
        
    def scan_ports(self, target_ip, start_port=1, end_port=1024):
        """Scan ports on target IP"""
        open_ports = []
        closed_ports = []
        
        for port in range(start_port, min(end_port + 1, 65536)):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                else:
                    closed_ports.append(port)
                    
                sock.close()
                
            except Exception as e:
                continue
                
        return open_ports, closed_ports
    
    def detect_port_scan(self, connections):
        """Detect potential port scanning activity"""
        current_time = time.time()
        threats = []
        
        # Group connections by source IP
        ip_ports = defaultdict(set)
        for conn in connections:
            if hasattr(conn, 'raddr') and conn.raddr:
                ip_ports[conn.raddr.ip].add(conn.raddr.port)
        
        # Check for suspicious port scanning patterns
        for ip, ports in ip_ports.items():
            if len(ports) > self.port_scan_threshold:
                self.port_scan_log[ip].append(current_time)
                # Clean old entries (older than 60 seconds)
                self.port_scan_log[ip] = [t for t in self.port_scan_log[ip] 
                                        if current_time - t < 60]
                
                if len(self.port_scan_log[ip]) > 5:  # Multiple scans in short time
                    threats.append({
                        'type': 'Port Scan',
                        'source_ip': ip,
                        'ports_scanned': len(ports),
                        'severity': 'HIGH',
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    self.suspicious_ips.add(ip)
        
        return threats
    
    def detect_ddos(self, connections):
        """Detect potential DDoS attacks"""
        current_time = time.time()
        threats = []
        
        # Count connections per IP
        ip_connections = defaultdict(int)
        for conn in connections:
            if hasattr(conn, 'raddr') and conn.raddr:
                ip_connections[conn.raddr.ip] += 1
        
        # Check for DDoS patterns
        for ip, conn_count in ip_connections.items():
            self.connection_log[ip].append(current_time)
            # Clean old entries (older than 60 seconds)
            self.connection_log[ip] = [t for t in self.connection_log[ip] 
                                     if current_time - t < 60]
            
            if len(self.connection_log[ip]) > self.connection_threshold:
                threats.append({
                    'type': 'DDoS Attack',
                    'source_ip': ip,
                    'connections_per_minute': len(self.connection_log[ip]),
                    'severity': 'CRITICAL',
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                })
                self.suspicious_ips.add(ip)
        
        return threats
    
    def analyze_traffic_patterns(self):
        """Analyze network traffic for unusual patterns"""
        threats = []
        
        try:
            # Get network statistics
            net_io = psutil.net_io_counters()
            current_time = time.time()
            
            # Calculate traffic rates
            if hasattr(self, 'last_net_io') and hasattr(self, 'last_check_time'):
                time_diff = current_time - self.last_check_time
                if time_diff > 0:
                    bytes_sent_rate = (net_io.bytes_sent - self.last_net_io.bytes_sent) / time_diff
                    bytes_recv_rate = (net_io.bytes_recv - self.last_net_io.bytes_recv) / time_diff
                    
                    # Check for unusual traffic spikes
                    if bytes_recv_rate > 10 * 1024 * 1024:  # 10 MB/s threshold
                        threats.append({
                            'type': 'Unusual Traffic',
                            'description': f'High incoming traffic: {bytes_recv_rate/1024/1024:.2f} MB/s',
                            'severity': 'MEDIUM',
                            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        })
            
            self.last_net_io = net_io
            self.last_check_time = current_time
            
        except Exception as e:
            pass
        
        return threats
    
    def get_network_connections(self):
        """Get current network connections"""
        try:
            return psutil.net_connections(kind='inet')
        except:
            return []
    
    def block_ip(self, ip_address):
        """Block suspicious IP address (simulation)"""
        self.blocked_ips.add(ip_address)
        return True

class VulnerabilityScanner:
    """Vulnerability scanning engine"""
    
    def __init__(self):
        self.common_ports = [21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 143, 443, 993, 995]
        self.vulnerabilities = []
    
    def scan_target(self, target_ip):
        """Comprehensive vulnerability scan"""
        results = {
            'target': target_ip,
            'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'services': {},
            'vulnerabilities': [],
            'recommendations': []
        }
        
        try:
            # Validate IP address
            ipaddress.ip_address(target_ip)
            
            # Port scan
            for port in self.common_ports:
                if self.scan_single_port(target_ip, port):
                    results['open_ports'].append(port)
                    service_info = self.identify_service(target_ip, port)
                    results['services'][port] = service_info
            
            # Vulnerability assessment
            results['vulnerabilities'] = self.assess_vulnerabilities(results['open_ports'], results['services'])
            results['recommendations'] = self.generate_recommendations(results['vulnerabilities'])
            
        except Exception as e:
            results['error'] = str(e)
        
        return results
    
    def scan_single_port(self, ip, port, timeout=1):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def identify_service(self, ip, port):
        """Identify service running on port"""
        service_info = {'name': 'Unknown', 'version': 'Unknown', 'banner': ''}
        
        try:
            service_info['name'] = socket.getservbyport(port)
        except:
            pass
        
        # Banner grabbing for common services
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            if port in [21, 22, 25, 110]:  # Services that send banners
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['banner'] = banner[:100]  # Limit banner length
            
            sock.close()
        except:
            pass
        
        return service_info
    
    def assess_vulnerabilities(self, open_ports, services):
        """Assess potential vulnerabilities"""
        vulnerabilities = []
        
        # Check for common vulnerable services
        vuln_checks = {
            21: 'FTP service detected - ensure secure configuration',
            23: 'Telnet service detected - use SSH instead',
            25: 'SMTP service detected - check for open relay',
            53: 'DNS service detected - ensure proper configuration',
            80: 'HTTP service detected - ensure HTTPS is available',
            110: 'POP3 service detected - use secure alternatives',
            143: 'IMAP service detected - ensure encryption'
        }
        
        for port in open_ports:
            if port in vuln_checks:
                vulnerabilities.append({
                    'port': port,
                    'service': services.get(port, {}).get('name', 'Unknown'),
                    'issue': vuln_checks[port],
                    'severity': 'MEDIUM'
                })
        
        # Check for specific version vulnerabilities
        for port, service in services.items():
            if 'banner' in service and service['banner']:
                if 'vsftpd 2.3.4' in service['banner'].lower():
                    vulnerabilities.append({
                        'port': port,
                        'service': service['name'],
                        'issue': 'Vulnerable FTP version detected',
                        'severity': 'HIGH'
                    })
        
        return vulnerabilities
    
    def generate_recommendations(self, vulnerabilities):
        """Generate security recommendations"""
        recommendations = []
        
        if vulnerabilities:
            recommendations.extend([
                'Update all services to latest versions',
                'Implement proper firewall rules',
                'Use encryption for all communications',
                'Regular security audits and monitoring',
                'Implement intrusion detection systems'
            ])
        else:
            recommendations.append('No immediate vulnerabilities detected, continue monitoring')
        
        return recommendations

class CyberSecurityGUI:
    """Main GUI application"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSecurity Defense Tool v1.0")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")
        
        # Initialize monitoring components
        self.network_monitor = NetworkMonitor()
        self.vulnerability_scanner = VulnerabilityScanner()
        self.monitoring_thread = None
        self.is_monitoring = False
        self.threat_queue = queue.Queue()
        
        # Configure styles
        self.setup_styles()
        
        # Create GUI
        self.create_widgets()
        
        # Start threat processing
        self.process_threats()
    
    def setup_styles(self):
        """Configure GUI styles for dark theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure dark theme colors
        style.configure('Dark.TFrame', background='#1e1e1e')
        style.configure('Dark.TLabel', background='#1e1e1e', foreground='#ffffff')
        style.configure('Dark.TButton', background='#333333', foreground='#ffffff')
        style.map('Dark.TButton', background=[('active', '#555555')])
        style.configure('Dark.TEntry', background='#333333', foreground='#ffffff')
        style.configure('Dark.TNotebook', background='#1e1e1e', foreground='#ffffff')
        style.configure('Dark.TNotebook.Tab', background='#333333', foreground='#ffffff')
        style.map('Dark.TNotebook.Tab', background=[('selected', '#555555')])
    
    def create_widgets(self):
        """Create main GUI widgets"""
        # Main title
        title_label = ttk.Label(self.root, text="CyberSecurity Defense Tool", 
                               font=('Arial', 16, 'bold'), style='Dark.TLabel')
        title_label.pack(pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root, style='Dark.TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_monitoring_tab()
        self.create_scanner_tab()
        self.create_threats_tab()
        self.create_settings_tab()
    
    def create_monitoring_tab(self):
        """Create network monitoring tab"""
        monitor_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(monitor_frame, text="Network Monitor")
        
        # Control panel
        control_frame = ttk.Frame(monitor_frame, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Target IP:", style='Dark.TLabel').pack(side=tk.LEFT, padx=5)
        self.monitor_ip_entry = ttk.Entry(control_frame, style='Dark.TEntry', width=15)
        self.monitor_ip_entry.pack(side=tk.LEFT, padx=5)
        self.monitor_ip_entry.insert(0, "127.0.0.1")
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                          command=self.toggle_monitoring, style='Dark.TButton')
        self.start_monitor_btn.pack(side=tk.LEFT, padx=10)
        
        self.clear_log_btn = ttk.Button(control_frame, text="Clear Log", 
                                       command=self.clear_monitor_log, style='Dark.TButton')
        self.clear_log_btn.pack(side=tk.LEFT, padx=5)
        
        # Status display
        status_frame = ttk.Frame(monitor_frame, style='Dark.TFrame')
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(status_frame, text="Status:", style='Dark.TLabel').pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, text="Stopped", 
                                     foreground='red', style='Dark.TLabel')
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(monitor_frame, text="Statistics", style='Dark.TFrame')
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.stats_text = tk.Text(stats_frame, height=6, bg='#333333', fg='#ffffff', 
                                 font=('Courier', 9))
        self.stats_text.pack(fill=tk.BOTH, padx=5, pady=5)
        
        # Monitor log
        log_frame = ttk.LabelFrame(monitor_frame, text="Activity Log", style='Dark.TFrame')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.monitor_log = scrolledtext.ScrolledText(log_frame, bg='#333333', fg='#ffffff', 
                                                    font=('Courier', 9))
        self.monitor_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_scanner_tab(self):
        """Create vulnerability scanner tab"""
        scanner_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(scanner_frame, text="Vulnerability Scanner")
        
        # Scanner controls
        control_frame = ttk.Frame(scanner_frame, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(control_frame, text="Target IP:", style='Dark.TLabel').pack(side=tk.LEFT, padx=5)
        self.scan_ip_entry = ttk.Entry(control_frame, style='Dark.TEntry', width=15)
        self.scan_ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.scan_btn = ttk.Button(control_frame, text="Start Scan", 
                                  command=self.start_vulnerability_scan, style='Dark.TButton')
        self.scan_btn.pack(side=tk.LEFT, padx=10)
        
        self.export_btn = ttk.Button(control_frame, text="Export Results", 
                                    command=self.export_scan_results, style='Dark.TButton')
        self.export_btn.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(scanner_frame, variable=self.progress_var, 
                                          maximum=100, length=300)
        self.progress_bar.pack(pady=10)
        
        # Results display
        results_frame = ttk.LabelFrame(scanner_frame, text="Scan Results", style='Dark.TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.scan_results = scrolledtext.ScrolledText(results_frame, bg='#333333', fg='#ffffff', 
                                                     font=('Courier', 9))
        self.scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_threats_tab(self):
        """Create threat analysis tab"""
        threats_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(threats_frame, text="Threat Analysis")
        
        # Threat controls
        control_frame = ttk.Frame(threats_frame, style='Dark.TFrame')
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.block_ip_btn = ttk.Button(control_frame, text="Block Selected IP", 
                                      command=self.block_selected_ip, style='Dark.TButton')
        self.block_ip_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_threats_btn = ttk.Button(control_frame, text="Clear Threats", 
                                           command=self.clear_threats, style='Dark.TButton')
        self.clear_threats_btn.pack(side=tk.LEFT, padx=5)
        
        # Threat summary
        summary_frame = ttk.LabelFrame(threats_frame, text="Threat Summary", style='Dark.TFrame')
        summary_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.threat_summary = tk.Text(summary_frame, height=4, bg='#333333', fg='#ffffff', 
                                     font=('Courier', 9))
        self.threat_summary.pack(fill=tk.X, padx=5, pady=5)
        
        # Detailed threats
        details_frame = ttk.LabelFrame(threats_frame, text="Detailed Threats", style='Dark.TFrame')
        details_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.threats_log = scrolledtext.ScrolledText(details_frame, bg='#333333', fg='#ffffff', 
                                                    font=('Courier', 9))
        self.threats_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_frame = ttk.Frame(self.notebook, style='Dark.TFrame')
        self.notebook.add(settings_frame, text="Settings")
        
        # Detection thresholds
        thresholds_frame = ttk.LabelFrame(settings_frame, text="Detection Thresholds", 
                                         style='Dark.TFrame')
        thresholds_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(thresholds_frame, text="Port Scan Threshold:", style='Dark.TLabel').grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.port_scan_threshold = tk.StringVar(value="10")
        ttk.Entry(thresholds_frame, textvariable=self.port_scan_threshold, 
                 style='Dark.TEntry', width=10).grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(thresholds_frame, text="Connection Threshold:", style='Dark.TLabel').grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.connection_threshold = tk.StringVar(value="100")
        ttk.Entry(thresholds_frame, textvariable=self.connection_threshold, 
                 style='Dark.TEntry', width=10).grid(row=1, column=1, padx=5, pady=5)
        
        # Apply settings button
        ttk.Button(thresholds_frame, text="Apply Settings", 
                  command=self.apply_settings, style='Dark.TButton').grid(row=2, column=0, columnspan=2, pady=10)
        
        # System information
        info_frame = ttk.LabelFrame(settings_frame, text="System Information", style='Dark.TFrame')
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.system_info = scrolledtext.ScrolledText(info_frame, bg='#333333', fg='#ffffff', 
                                                    font=('Courier', 9))
        self.system_info.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.update_system_info()
    
    def toggle_monitoring(self):
        """Toggle network monitoring"""
        if not self.is_monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.monitor_ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        self.is_monitoring = True
        self.network_monitor.is_monitoring = True
        self.start_monitor_btn.configure(text="Stop Monitoring")
        self.status_label.configure(text="Running", foreground='green')
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitoring_worker, 
                                                 args=(target_ip,), daemon=True)
        self.monitoring_thread.start()
        
        self.log_message("Network monitoring started for " + target_ip)
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        self.network_monitor.is_monitoring = False
        self.start_monitor_btn.configure(text="Start Monitoring")
        self.status_label.configure(text="Stopped", foreground='red')
        self.log_message("Network monitoring stopped")
    
    def monitoring_worker(self, target_ip):
        """Background monitoring worker"""
        while self.is_monitoring:
            try:
                # Get network connections
                connections = self.network_monitor.get_network_connections()
                
                # Detect threats
                port_scan_threats = self.network_monitor.detect_port_scan(connections)
                ddos_threats = self.network_monitor.detect_ddos(connections)
                traffic_threats = self.network_monitor.analyze_traffic_patterns()
                
                # Queue threats for processing
                all_threats = port_scan_threats + ddos_threats + traffic_threats
                for threat in all_threats:
                    self.threat_queue.put(threat)
                
                # Update statistics
                self.update_statistics(connections)
                
                time.sleep(1)  # Check every second
                
            except Exception as e:
                self.log_message(f"Monitoring error: {str(e)}")
                time.sleep(5)
    
    def start_vulnerability_scan(self):
        """Start vulnerability scan"""
        target_ip = self.scan_ip_entry.get().strip()
        if not target_ip:
            messagebox.showerror("Error", "Please enter a target IP address")
            return
        
        self.scan_btn.configure(state='disabled', text="Scanning...")
        self.progress_var.set(0)
        
        # Start scan in background thread
        scan_thread = threading.Thread(target=self.scan_worker, args=(target_ip,), daemon=True)
        scan_thread.start()
    
    def scan_worker(self, target_ip):
        """Background scan worker"""
        try:
            # Perform vulnerability scan
            results = self.vulnerability_scanner.scan_target(target_ip)
            
            # Update progress
            self.root.after(0, lambda: self.progress_var.set(100))
            
            # Display results
            self.root.after(0, lambda: self.display_scan_results(results))
            
        except Exception as e:
            error_msg = f"Scan error: {str(e)}"
            self.root.after(0, lambda: messagebox.showerror("Scan Error", error_msg))
        
        finally:
            self.root.after(0, lambda: self.scan_btn.configure(state='normal', text="Start Scan"))
    
    def display_scan_results(self, results):
        """Display vulnerability scan results"""
        self.scan_results.delete(1.0, tk.END)
        
        output = f"=== Vulnerability Scan Results ===\n"
        output += f"Target: {results['target']}\n"
        output += f"Timestamp: {results['timestamp']}\n\n"
        
        if 'error' in results:
            output += f"Error: {results['error']}\n"
        else:
            output += f"Open Ports: {', '.join(map(str, results['open_ports'])) if results['open_ports'] else 'None'}\n\n"
            
            if results['services']:
                output += "Services Detected:\n"
                for port, service in results['services'].items():
                    output += f"  Port {port}: {service['name']}\n"
                    if service['banner']:
                        output += f"    Banner: {service['banner']}\n"
                output += "\n"
            
            if results['vulnerabilities']:
                output += "Vulnerabilities Found:\n"
                for vuln in results['vulnerabilities']:
                    output += f"  [{vuln['severity']}] Port {vuln['port']} ({vuln['service']}): {vuln['issue']}\n"
                output += "\n"
            
            if results['recommendations']:
                output += "Recommendations:\n"
                for rec in results['recommendations']:
                    output += f"  - {rec}\n"
        
        self.scan_results.insert(tk.END, output)
    
    def process_threats(self):
        """Process threats from queue"""
        try:
            while not self.threat_queue.empty():
                threat = self.threat_queue.get_nowait()
                self.display_threat(threat)
        except queue.Empty:
            pass
        
        # Schedule next check
        self.root.after(1000, self.process_threats)
    
    def display_threat(self, threat):
        """Display detected threat"""
        threat_msg = f"[{threat['timestamp']}] {threat['type']} - {threat['severity']}\n"
        
        if 'source_ip' in threat:
            threat_msg += f"  Source IP: {threat['source_ip']}\n"
        
        for key, value in threat.items():
            if key not in ['type', 'severity', 'timestamp', 'source_ip']:
                threat_msg += f"  {key.replace('_', ' ').title()}: {value}\n"
        
        threat_msg += "\n"
        
        self.threats_log.insert(tk.END, threat_msg)
        self.threats_log.see(tk.END)
        
        self.log_message(f"THREAT DETECTED: {threat['type']} from {threat.get('source_ip', 'Unknown')}")
    
    def update_statistics(self, connections):
        """Update monitoring statistics"""
        stats = f"Active Connections: {len(connections)}\n"
        stats += f"Suspicious IPs: {len(self.network_monitor.suspicious_ips)}\n"
        stats += f"Blocked IPs: {len(self.network_monitor.blocked_ips)}\n"
        stats += f"Monitoring Status: {'Active' if self.is_monitoring else 'Inactive'}\n"
        
        # Network I/O stats
        try:
            net_io = psutil.net_io_counters()
            stats += f"Bytes Sent: {net_io.bytes_sent:,}\n"
            stats += f"Bytes Received: {net_io.bytes_recv:,}\n"
        except:
            pass
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats)
    
    def log_message(self, message):
        """Log message to monitor log"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        self.monitor_log.insert(tk.END, log_entry)
        self.monitor_log.see(tk.END)
    
    def clear_monitor_log(self):
        """Clear monitoring log"""
        self.monitor_log.delete(1.0, tk.END)
    
    def clear_threats(self):
        """Clear threats log"""
        self.threats_log.delete(1.0, tk.END)
        self.network_monitor.suspicious_ips.clear()
    
    def block_selected_ip(self):
        """Block selected IP address"""
        # Get selected text from threats log
        try:
            selected_text = self.threats_log.selection_get()
            # Extract IP addresses from selected text
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, selected_text)
            
            if ips:
                ip_to_block = ips[0]  # Block first IP found
                if self.network_monitor.block_ip(ip_to_block):
                    self.log_message(f"Blocked IP: {ip_to_block}")
                    messagebox.showinfo("Success", f"IP {ip_to_block} has been blocked")
                else:
                    messagebox.showerror("Error", f"Failed to block IP {ip_to_block}")
            else:
                messagebox.showwarning("Warning", "No IP address found in selection")
        except tk.TclError:
            messagebox.showwarning("Warning", "Please select text containing an IP address")
    
    def apply_settings(self):
        """Apply configuration settings"""
        try:
            port_threshold = int(self.port_scan_threshold.get())
            conn_threshold = int(self.connection_threshold.get())
            
            self.network_monitor.port_scan_threshold = port_threshold
            self.network_monitor.connection_threshold = conn_threshold
            
            messagebox.showinfo("Success", "Settings applied successfully")
            self.log_message("Configuration settings updated")
        except ValueError:
            messagebox.showerror("Error", "Invalid threshold values")
    
    def export_scan_results(self):
        """Export scan results to file"""
        try:
            results = self.scan_results.get(1.0, tk.END)
            if results.strip():
                filename = f"scan_results_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w') as f:
                    f.write(results)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            else:
                messagebox.showwarning("Warning", "No scan results to export")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")
    
    def update_system_info(self):
        """Update system information display"""
        info = f"=== System Information ===\n"
        info += f"Platform: {platform.system()} {platform.release()}\n"
        info += f"Architecture: {platform.machine()}\n"
        info += f"Processor: {platform.processor()}\n"
        info += f"Python Version: {platform.python_version()}\n\n"
        
        # Memory information
        try:
            memory = psutil.virtual_memory()
            info += f"Total Memory: {memory.total / (1024**3):.2f} GB\n"
            info += f"Available Memory: {memory.available / (1024**3):.2f} GB\n"
            info += f"Memory Usage: {memory.percent}%\n\n"
        except:
            info += "Memory information unavailable\n\n"
        
        # Network interfaces
        try:
            interfaces = psutil.net_if_addrs()
            info += "Network Interfaces:\n"
            for interface, addrs in interfaces.items():
                info += f"  {interface}:\n"
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        info += f"    IPv4: {addr.address}\n"
                    elif addr.family == socket.AF_INET6:
                        info += f"    IPv6: {addr.address}\n"
        except:
            info += "Network interface information unavailable\n"
        
        self.system_info.delete(1.0, tk.END)
        self.system_info.insert(tk.END, info)

class ThreatIntelligence:
    """Threat intelligence and analysis module"""
    
    def __init__(self):
        self.threat_database = {
            'malicious_ips': set(),
            'suspicious_ports': {1433, 3389, 5432, 1521},  # Common attack targets
            'known_vulnerabilities': {},
            'attack_patterns': []
        }
        self.load_threat_intelligence()
    
    def load_threat_intelligence(self):
        """Load threat intelligence data"""
        # Simulate loading threat intelligence
        self.threat_database['malicious_ips'].update([
            '192.168.1.100',  # Example malicious IPs
            '10.0.0.50',
            '172.16.0.25'
        ])
        
        self.threat_database['known_vulnerabilities'] = {
            'CVE-2021-44228': {
                'description': 'Log4j Remote Code Execution',
                'severity': 'CRITICAL',
                'affected_services': ['Apache', 'Java applications']
            },
            'CVE-2021-34527': {
                'description': 'Windows Print Spooler Privilege Escalation',
                'severity': 'HIGH',
                'affected_services': ['Windows Print Spooler']
            }
        }
    
    def check_ip_reputation(self, ip_address):
        """Check IP address reputation"""
        if ip_address in self.threat_database['malicious_ips']:
            return {
                'status': 'MALICIOUS',
                'confidence': 'HIGH',
                'reason': 'Known malicious IP in threat database'
            }
        
        # Check for private IP ranges
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private:
                return {
                    'status': 'INTERNAL',
                    'confidence': 'HIGH',
                    'reason': 'Private IP address'
                }
        except:
            pass
        
        return {
            'status': 'UNKNOWN',
            'confidence': 'LOW',
            'reason': 'No reputation data available'
        }
    
    def analyze_attack_pattern(self, events):
        """Analyze events for attack patterns"""
        patterns = []
        
        # Check for coordinated attacks
        if len(events) > 5:
            source_ips = [event.get('source_ip') for event in events if 'source_ip' in event]
            unique_ips = set(source_ips)
            
            if len(unique_ips) > 3:
                patterns.append({
                    'type': 'Distributed Attack',
                    'description': f'Attack from {len(unique_ips)} different sources',
                    'severity': 'HIGH'
                })
        
        return patterns

class SecurityReporter:
    """Security reporting and alerting module"""
    
    def __init__(self):
        self.reports = []
        self.alert_threshold = {
            'CRITICAL': 0,  # Immediate alert
            'HIGH': 1,      # Alert after 1 occurrence
            'MEDIUM': 5,    # Alert after 5 occurrences
            'LOW': 10       # Alert after 10 occurrences
        }
    
    def generate_security_report(self, threats, vulnerabilities, timeframe='24h'):
        """Generate comprehensive security report"""
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        report = {
            'timestamp': timestamp,
            'timeframe': timeframe,
            'summary': {
                'total_threats': len(threats),
                'critical_threats': len([t for t in threats if t.get('severity') == 'CRITICAL']),
                'high_threats': len([t for t in threats if t.get('severity') == 'HIGH']),
                'medium_threats': len([t for t in threats if t.get('severity') == 'MEDIUM']),
                'low_threats': len([t for t in threats if t.get('severity') == 'LOW']),
                'total_vulnerabilities': len(vulnerabilities)
            },
            'threats': threats,
            'vulnerabilities': vulnerabilities,
            'recommendations': self.generate_recommendations(threats, vulnerabilities)
        }
        
        self.reports.append(report)
        return report
    
    def generate_recommendations(self, threats, vulnerabilities):
        """Generate security recommendations based on findings"""
        recommendations = []
        
        if any(t.get('type') == 'DDoS Attack' for t in threats):
            recommendations.append("Implement DDoS mitigation strategies")
            recommendations.append("Consider using a CDN or DDoS protection service")
        
        if any(t.get('type') == 'Port Scan' for t in threats):
            recommendations.append("Review firewall rules and close unnecessary ports")
            recommendations.append("Implement port knocking or port hiding techniques")
        
        if vulnerabilities:
            recommendations.append("Prioritize patching of identified vulnerabilities")
            recommendations.append("Implement regular vulnerability scanning schedule")
        
        if not recommendations:
            recommendations.append("Continue monitoring and maintain current security posture")
        
        return recommendations
    
    def should_alert(self, threat):
        """Check if threat should trigger an alert"""
        severity = threat.get('severity', 'LOW')
        return True  # For demo purposes, alert on all threats

class NetworkFirewall:
    """Basic network firewall simulation"""
    
    def __init__(self):
        self.rules = []
        self.blocked_ips = set()
        self.allowed_ports = {22, 80, 443}  # SSH, HTTP, HTTPS
    
    def add_rule(self, rule_type, source_ip=None, destination_port=None, action='BLOCK'):
        """Add firewall rule"""
        rule = {
            'id': len(self.rules) + 1,
            'type': rule_type,
            'source_ip': source_ip,
            'destination_port': destination_port,
            'action': action,
            'created': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        self.rules.append(rule)
        return rule
    
    def block_ip(self, ip_address):
        """Block IP address"""
        self.blocked_ips.add(ip_address)
        return self.add_rule('IP_BLOCK', source_ip=ip_address)
    
    def check_connection(self, source_ip, destination_port):
        """Check if connection should be allowed"""
        if source_ip in self.blocked_ips:
            return False, "IP blocked by firewall"
        
        if destination_port not in self.allowed_ports:
            return False, f"Port {destination_port} not allowed"
        
        return True, "Connection allowed"

def main():
    """Main application entry point"""
    # Check for required dependencies
    required_modules = ['psutil', 'tkinter']
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
        except ImportError:
            missing_modules.append(module)
    
    if missing_modules:
        print(f"Missing required modules: {', '.join(missing_modules)}")
        print("Please install missing modules using: pip install " + ' '.join(missing_modules))
        return
    
    # Create and run the application
    root = tk.Tk()
    app = CyberSecurityGUI(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
    except Exception as e:
        print(f"Application error: {str(e)}")

if __name__ == "__main__":
    # Security notice
    print("=" * 60)
    print("CyberSecurity Defense Tool v1.0")
    print("=" * 60)
    print("IMPORTANT: This tool is for educational and authorized")
    print("security testing purposes only. Only use on networks")
    print("and systems you own or have explicit permission to test.")
    print("=" * 60)
    print()
    
    main()