import socket
import ssl
import subprocess
import os
from datetime import datetime


class PCIScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.results = []

    # ── REQUIREMENT 1: Firewall – check for dangerous open ports ──
    def check_open_ports(self):
        dangerous_ports = {
            23:  ("Telnet", "Critical"),
            21:  ("FTP", "High"),
            69:  ("TFTP", "High"),
            161: ("SNMP", "Medium"),
            512: ("rexec", "Critical"),
            513: ("rlogin", "Critical"),
        }
        for port, (service, risk) in dangerous_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    self.results.append({
                        "requirement": "PCI-DSS 1.2",
                        "description": f"Dangerous port {port} ({service}) is OPEN",
                        "status": "FAIL",
                        "evidence": f"Port {port} responded on {self.target_ip}",
                        "risk_level": risk
                    })
                else:
                    self.results.append({
                        "requirement": "PCI-DSS 1.2",
                        "description": f"Port {port} ({service}) is closed",
                        "status": "PASS",
                        "evidence": f"Port {port} did not respond on {self.target_ip}",
                        "risk_level": "Low"
                    })
                sock.close()
                
            except Exception as e:
                self.results.append({
                    "requirement":"PCI-DSS 1.2",
                    "description": f"could not check for port {port}({service})",
                    "status": "WARNING",
                    "evidence": str(e),
                    "risk_level": "Medium"
                    
                })

    # ── REQUIREMENT 2: No vendor defaults ──
    def check_default_services(self):
        default_services = {
            22:   ("SSH",        "Medium"),
            80:   ("HTTP",       "Medium"),
            3306: ("MySQL",      "High"),
            5432: ("PostgreSQL", "High"),
            27017:("MongoDB",    "High"),
        }
        for port, (service, risk) in default_services.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    self.results.append({
                        "requirement": "PCI-DSS 2.1",
                        "description": f"{service} service detected on port {port}",
                        "status": "WARNING",
                        "evidence": f"Port {port} open — verify default credentials are changed",
                        "risk_level": risk
                    })
                else:
                    self.results.append({
                        "requirement": "PCI-DSS 2.1",
                        "description": f"{service} not exposed on port {port}",
                        "status": "PASS",
                        "evidence": f"Port {port} is closed",
                        "risk_level": "Low"
                    })
                sock.close()
                
            except Exception as e:
                self.results.append({
                    "requirement":"PCI-DSS 1.2",
                    "description": f"could not check for port {port}({service})",
                    "status": "WARNING",
                    "evidence": str(e),
                    "risk_level": "Medium"
                    
                })

            

    # ── REQUIREMENT 3: Protect stored data ──
    def check_stored_data(self):
        sensitive_patterns = ["cardnumber", "cvv", "pan", "credit_card", "card_data"]
        found_files = []
        search_dirs = ["/tmp", "/var/www", "/home"]
        for directory in search_dirs:
            if os.path.exists(directory):
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        if file.endswith(('.txt', '.csv', '.log', '.sql')):
                            for pattern in sensitive_patterns:
                                if pattern in file.lower():
                                    found_files.append(os.path.join(root, file))
        if found_files:
            self.results.append({
                "requirement": "PCI-DSS 3.2",
                "description": "Potential cardholder data files found",
                "status": "FAIL",
                "evidence": f"Suspicious files: {', '.join(found_files[:3])}",
                "risk_level": "Critical"
            })
        else:
            self.results.append({
                "requirement": "PCI-DSS 3.2",
                "description": "No suspicious cardholder data files found",
                "status": "PASS",
                "evidence": "Checked /tmp, /var/www, /home for sensitive filenames",
                "risk_level": "Low"
            })

    # ── REQUIREMENT 4: Encrypt transmissions – check TLS version ──
    def check_ssl_tls(self):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_ip, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                    version = ssock.version()
                    if version in ["TLSv1", "TLSv1.1", "SSLv3"]:
                        self.results.append({
                            "requirement": "PCI-DSS 4.1",
                            "description": f"Weak TLS version detected: {version}",
                            "status": "FAIL",
                            "evidence": f"Server is using {version} on port 443",
                            "risk_level": "High"
                        })
                    else:
                        self.results.append({
                            "requirement": "PCI-DSS 4.1",
                            "description": f"Strong TLS version in use: {version}",
                            "status": "PASS",
                            "evidence": f"Server is using {version} on port 443",
                            "risk_level": "Low"
                        })
        except Exception as e:
            self.results.append({
                "requirement": "PCI-DSS 4.1",
                "description": "HTTPS/TLS could not be verified",
                "status": "WARNING",
                "evidence": str(e),
                "risk_level": "Medium"
            })

    # ── REQUIREMENT 5: Anti-malware ──
    def check_antivirus(self):
        av_tools = ["clamav", "clamscan", "freshclam", "rkhunter", "chkrootkit"]
        found = []
        for tool in av_tools:
            result = subprocess.run(
                ["which", tool],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                found.append(tool)
        if found:
            self.results.append({
                "requirement": "PCI-DSS 5.1",
                "description": f"Anti-malware tool(s) detected: {', '.join(found)}",
                "status": "PASS",
                "evidence": f"Found: {', '.join(found)}",
                "risk_level": "Low"
            })
        else:
            self.results.append({
                "requirement": "PCI-DSS 5.1",
                "description": "No anti-malware tools found on system",
                "status": "FAIL",
                "evidence": "Checked for clamav, rkhunter, chkrootkit — none found",
                "risk_level": "High"
            })

    # ── REQUIREMENT 6: Secure systems & software ──
    def check_system_updates(self):
        try:
            result = subprocess.run(
                ["apt-get", "-s", "upgrade"],
                capture_output=True, text=True
            )
            lines = result.stdout.splitlines()
            upgradable = [l for l in lines if l.startswith("Inst")]
            count = len(upgradable)
            if count == 0:
                self.results.append({
                    "requirement": "PCI-DSS 6.3",
                    "description": "System is fully up to date",
                    "status": "PASS",
                    "evidence": "No pending updates found via apt-get",
                    "risk_level": "Low"
                })
            elif count <= 5:
                self.results.append({
                    "requirement": "PCI-DSS 6.3",
                    "description": f"{count} pending system update(s) found",
                    "status": "WARNING",
                    "evidence": f"{count} packages can be upgraded",
                    "risk_level": "Medium"
                })
            else:
                self.results.append({
                    "requirement": "PCI-DSS 6.3",
                    "description": f"{count} pending system updates found",
                    "status": "FAIL",
                    "evidence": f"{count} packages need upgrading",
                    "risk_level": "High"
                })
        except Exception as e:
            self.results.append({
                "requirement": "PCI-DSS 6.3",
                "description": "Could not check system updates",
                "status": "WARNING",
                "evidence": str(e),
                "risk_level": "Medium"
            })

    # ── REQUIREMENT 7: Restrict access to system components ──
    def check_file_permissions(self):
        sensitive_files = {
            "/etc/passwd":          "644",
            "/etc/shadow":          "640",
            "/etc/ssh/sshd_config": "600",
        }
        for filepath, expected in sensitive_files.items():
            if os.path.exists(filepath):
                actual = oct(os.stat(filepath).st_mode)[-3:]
                if actual <= expected:
                    self.results.append({
                        "requirement": "PCI-DSS 7.2",
                        "description": f"File permissions OK: {filepath}",
                        "status": "PASS",
                        "evidence": f"{filepath} has permissions {actual}",
                        "risk_level": "Low"
                    })
                else:
                    self.results.append({
                        "requirement": "PCI-DSS 7.2",
                        "description": f"Insecure permissions on {filepath}",
                        "status": "FAIL",
                        "evidence": f"{filepath} has {actual}, expected {expected} or stricter",
                        "risk_level": "High"
                    })
            else:
                self.results.append({
                    "requirement": "PCI-DSS 7.2",
                    "description": f"File not found: {filepath}",
                    "status": "WARNING",
                    "evidence": f"{filepath} does not exist on this system",
                    "risk_level": "Medium"
                })

    # ── REQUIREMENT 8: Access control – check password policy ──
    def check_password_policy(self):
        try:
            with open("/etc/login.defs", "r") as f:
                content = f.read()
            min_length = None
            max_days   = None
            for line in content.splitlines():
                if line.startswith("PASS_MIN_LEN"):
                    min_length = int(line.split()[1])
                if line.startswith("PASS_MAX_DAYS"):
                    max_days = int(line.split()[1])
            if min_length is not None:
                status = "PASS" if min_length >= 8 else "FAIL"
                self.results.append({
                    "requirement": "PCI-DSS 8.3.6",
                    "description": f"Minimum password length is {min_length}",
                    "status": status,
                    "evidence": f"PASS_MIN_LEN={min_length} in /etc/login.defs",
                    "risk_level": "Low" if status == "PASS" else "High"
                })
            if max_days is not None:
                status = "PASS" if max_days <= 90 else "FAIL"
                self.results.append({
                    "requirement": "PCI-DSS 8.3.9",
                    "description": f"Password expiry set to {max_days} days",
                    "status": status,
                    "evidence": f"PASS_MAX_DAYS={max_days} in /etc/login.defs",
                    "risk_level": "Low" if status == "PASS" else "Medium"
                })
        except Exception as e:
            self.results.append({
                "requirement": "PCI-DSS 8.3",
                "description": "Password policy could not be read",
                "status": "WARNING",
                "evidence": str(e),
                "risk_level": "Medium"
            })

    # ── REQUIREMENT 9: Physical access (policy checklist) ──
    def check_physical_access(self):
        self.results.append({
            "requirement": "PCI-DSS 9.1",
            "description": "Physical access controls require manual verification",
            "status": "WARNING",
            "evidence": "Verify: locked server rooms, CCTV, visitor logs, badge access",
            "risk_level": "Medium"
        })

    # ── REQUIREMENT 10: Audit logs – check if logging is enabled ──
    def check_audit_logs(self):
        log_files = [
            "/var/log/auth.log",
            "/var/log/syslog",
            "/var/log/audit/audit.log"
        ]
        found = False
        for log in log_files:
            if os.path.exists(log):
                found = True
                self.results.append({
                    "requirement": "PCI-DSS 10.2",
                    "description": f"Audit log found: {log}",
                    "status": "PASS",
                    "evidence": f"Log file exists at {log}",
                    "risk_level": "Low"
                })
                break
        if not found:
            self.results.append({
                "requirement": "PCI-DSS 10.2",
                "description": "No audit log files found on system",
                "status": "FAIL",
                "evidence": "Checked /var/log/auth.log, syslog, audit.log",
                "risk_level": "Critical"
            })

    # ── REQUIREMENT 11: Regular testing & vulnerability scans ──
    def check_vulnerability_scan(self):
        vuln_tools = ["nmap", "nikto", "openvas", "lynis"]
        found = []
        for tool in vuln_tools:
            result = subprocess.run(
                ["which", tool],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                found.append(tool)
        if found:
            self.results.append({
                "requirement": "PCI-DSS 11.3",
                "description": f"Vulnerability scanning tool(s) available: {', '.join(found)}",
                "status": "PASS",
                "evidence": f"Found tools: {', '.join(found)}",
                "risk_level": "Low"
            })
        else:
            self.results.append({
                "requirement": "PCI-DSS 11.3",
                "description": "No vulnerability scanning tools found",
                "status": "FAIL",
                "evidence": "Checked for nmap, nikto, openvas, lynis — none found",
                "risk_level": "High"
            })

    # ── REQUIREMENT 12: Security policy documentation ──
    def check_security_policy(self):
        policy_files = [
            "/etc/security/policy.txt",
            "/etc/security/compliance.txt",
            "/var/www/policy.pdf"
        ]
        found = False
        for policy in policy_files:
            if os.path.exists(policy):
                found = True
                self.results.append({
                    "requirement": "PCI-DSS 12.1",
                    "description": "Security policy document found",
                    "status": "PASS",
                    "evidence": f"Policy file exists at {policy}",
                    "risk_level": "Low"
                })
                break
        if not found:
            self.results.append({
                "requirement": "PCI-DSS 12.1",
                "description": "No security policy document found",
                "status": "WARNING",
                "evidence": "No policy file found — ensure documented policy exists",
                "risk_level": "Medium"
            })

    # ── RUN ALL 12 CHECKS ──
    def run_all_checks(self):
        self.check_open_ports()           # Requirement 1
        self.check_default_services()     # Requirement 2
        self.check_stored_data()          # Requirement 3
        self.check_ssl_tls()              # Requirement 4
        self.check_antivirus()            # Requirement 5
        self.check_system_updates()       # Requirement 6
        self.check_file_permissions()     # Requirement 7
        self.check_password_policy()      # Requirement 8
        self.check_physical_access()      # Requirement 9
        self.check_audit_logs()           # Requirement 10
        self.check_vulnerability_scan()   # Requirement 11
        self.check_security_policy()      # Requirement 12
        return self.results