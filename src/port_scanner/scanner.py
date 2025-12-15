"""
Network Port Scanner Module
Scans network ports and identifies services
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple
from datetime import datetime
import ipaddress


class PortScanner:
    """Network port scanner with service detection"""
    
    # Common ports and services
    COMMON_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
        5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
        8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    
    # Well-known port ranges
    WELL_KNOWN_PORTS = range(1, 1024)
    REGISTERED_PORTS = range(1024, 49152)
    
    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        """Initialize port scanner"""
        self.timeout = timeout
        self.max_workers = max_workers
        self.scan_results = []
    
    def validate_target(self, target: str) -> Tuple[bool, str]:
        """Validate target IP or hostname"""
        try:
            # Try to resolve hostname
            ip = socket.gethostbyname(target)
            # Validate IP
            ipaddress.ip_address(ip)
            return True, ip
        except socket.gaierror:
            return False, "Invalid hostname"
        except ValueError:
            return False, "Invalid IP address"
        except Exception as e:
            return False, str(e)
    
    def scan_port(self, target: str, port: int) -> Dict:
        """Scan a single port"""
        result = {
            'port': port,
            'state': 'closed',
            'service': self.COMMON_PORTS.get(port, 'Unknown'),
            'banner': None
        }
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            connection_result = sock.connect_ex((target, port))
            
            if connection_result == 0:
                result['state'] = 'open'
                
                # Try to grab banner
                try:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner:
                        result['banner'] = banner[:100]  # Limit banner length
                except:
                    pass
            
            sock.close()
        
        except socket.timeout:
            result['state'] = 'filtered'
        except socket.error:
            result['state'] = 'closed'
        except Exception as e:
            result['state'] = 'error'
            result['banner'] = str(e)
        
        return result
    
    def scan_port_range(self, target: str, start_port: int, end_port: int) -> List[Dict]:
        """Scan a range of ports using thread pool"""
        # Validate target
        valid, ip = self.validate_target(target)
        if not valid:
            raise ValueError(f"Invalid target: {ip}")
        
        print(f"\n🔍 Scanning {target} ({ip})")
        print(f"📊 Port range: {start_port}-{end_port}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        open_ports = []
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all port scans
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in range(start_port, end_port + 1)
            }
            
            # Collect results
            completed = 0
            total = end_port - start_port + 1
            
            for future in concurrent.futures.as_completed(future_to_port):
                completed += 1
                result = future.result()
                
                # Only keep open or filtered ports
                if result['state'] in ['open', 'filtered']:
                    open_ports.append(result)
                    status_icon = '🟢' if result['state'] == 'open' else '🟡'
                    print(f"{status_icon} Port {result['port']}: {result['state'].upper()} "
                          f"({result['service']})")
                
                # Progress indicator
                if completed % 100 == 0:
                    print(f"⏳ Progress: {completed}/{total} ports scanned...")
        
        print(f"\n✅ Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"📈 Found {len(open_ports)} open/filtered ports\n")
        
        self.scan_results = open_ports
        return open_ports
    
    def scan_common_ports(self, target: str) -> List[Dict]:
        """Scan commonly used ports"""
        ports = sorted(self.COMMON_PORTS.keys())
        
        valid, ip = self.validate_target(target)
        if not valid:
            raise ValueError(f"Invalid target: {ip}")
        
        print(f"\n🔍 Quick scan of common ports on {target} ({ip})")
        print(f"📊 Scanning {len(ports)} common ports\n")
        
        open_ports = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port 
                for port in ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                
                if result['state'] == 'open':
                    open_ports.append(result)
                    print(f"🟢 Port {result['port']}: OPEN ({result['service']})")
        
        print(f"\n✅ Quick scan completed")
        print(f"📈 Found {len(open_ports)} open ports\n")
        
        self.scan_results = open_ports
        return open_ports
    
    def generate_report(self) -> str:
        """Generate a formatted scan report"""
        if not self.scan_results:
            return "No scan results available"
        
        report = []
        report.append("=" * 70)
        report.append("PORT SCAN REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Ports Found: {len(self.scan_results)}\n")
        
        # Group by state
        open_ports = [p for p in self.scan_results if p['state'] == 'open']
        filtered_ports = [p for p in self.scan_results if p['state'] == 'filtered']
        
        if open_ports:
            report.append("🟢 OPEN PORTS:")
            report.append("-" * 70)
            for port_info in sorted(open_ports, key=lambda x: x['port']):
                report.append(f"  Port {port_info['port']:5d} | "
                            f"{port_info['service']:15s} | "
                            f"State: {port_info['state'].upper()}")
                if port_info['banner']:
                    report.append(f"    Banner: {port_info['banner'][:60]}...")
            report.append("")
        
        if filtered_ports:
            report.append("🟡 FILTERED PORTS:")
            report.append("-" * 70)
            for port_info in sorted(filtered_ports, key=lambda x: x['port']):
                report.append(f"  Port {port_info['port']:5d} | "
                            f"{port_info['service']:15s} | "
                            f"State: {port_info['state'].upper()}")
            report.append("")
        
        report.append("=" * 70)
        
        return "\n".join(report)
    
    def get_security_summary(self) -> Dict:
        """Generate security summary of scan results"""
        if not self.scan_results:
            return {'risk_level': 'Unknown', 'issues': []}
        
        open_ports = [p for p in self.scan_results if p['state'] == 'open']
        
        # Define risky ports
        high_risk_ports = {21, 23, 445, 3389, 5900}  # FTP, Telnet, SMB, RDP, VNC
        medium_risk_ports = {22, 3306, 5432, 6379, 27017}  # SSH, DBs, Redis, MongoDB
        
        high_risk_found = [p for p in open_ports if p['port'] in high_risk_ports]
        medium_risk_found = [p for p in open_ports if p['port'] in medium_risk_ports]
        
        issues = []
        
        if high_risk_found:
            issues.append(f"⚠️ HIGH RISK: {len(high_risk_found)} high-risk ports open "
                         f"({', '.join(str(p['port']) for p in high_risk_found)})")
        
        if medium_risk_found:
            issues.append(f"⚡ MEDIUM RISK: {len(medium_risk_found)} medium-risk ports open "
                         f"({', '.join(str(p['port']) for p in medium_risk_found)})")
        
        if 23 in [p['port'] for p in open_ports]:
            issues.append("🚨 CRITICAL: Telnet (23) is open - unencrypted protocol!")
        
        if 21 in [p['port'] for p in open_ports]:
            issues.append("🚨 CRITICAL: FTP (21) is open - consider SFTP instead")
        
        # Determine risk level
        if len(high_risk_found) > 0:
            risk_level = "HIGH"
        elif len(medium_risk_found) > 2:
            risk_level = "MEDIUM"
        elif len(open_ports) > 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_level': risk_level,
            'open_ports_count': len(open_ports),
            'high_risk_ports': len(high_risk_found),
            'medium_risk_ports': len(medium_risk_found),
            'issues': issues
        }


def main():
    """Test the port scanner"""
    scanner = PortScanner(timeout=0.5)
    
    # Example: Scan localhost
    target = "127.0.0.1"
    
    print("=" * 70)
    print("NETWORK PORT SCANNER - TEST")
    print("=" * 70)
    
    try:
        # Scan common ports
        results = scanner.scan_common_ports(target)
        
        # Print report
        print(scanner.generate_report())
        
        # Security summary
        summary = scanner.get_security_summary()
        print(f"\n🛡️ SECURITY SUMMARY:")
        print(f"Risk Level: {summary['risk_level']}")
        print(f"Open Ports: {summary['open_ports_count']}")
        if summary['issues']:
            print("\nSecurity Issues:")
            for issue in summary['issues']:
                print(f"  {issue}")
    
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()