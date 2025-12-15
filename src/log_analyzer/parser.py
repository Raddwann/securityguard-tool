"""
Log File Parser and Analyzer
Parses and analyzes security logs for suspicious activity
"""

import re
from typing import List, Dict, Tuple
from datetime import datetime
from collections import Counter, defaultdict


class LogAnalyzer:
    """Analyzes security logs for suspicious patterns"""
    
    # Common log patterns
    LOG_PATTERNS = {
        'ssh_failed': r'Failed password for (\w+) from ([\d.]+)',
        'ssh_accepted': r'Accepted password for (\w+) from ([\d.]+)',
        'sudo': r'sudo:\s+(\w+) : TTY=(\w+) ; PWD=([^;]+) ; USER=(\w+) ; COMMAND=(.+)',
        'apache_error': r'\[([\w\s:]+)\] \[(\w+)\] (.+)',
        'apache_access': r'([\d.]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)',
        'firewall_block': r'BLOCK.*SRC=([\d.]+).*DST=([\d.]+).*PROTO=(\w+).*DPT=(\d+)',
        'login_attempt': r'authentication failure.*user=(\w+).*rhost=([\d.]+)'
    }
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = {
        'sql_injection': r'(union|select|insert|update|delete|drop|create|alter).*from',
        'xss_attempt': r'<script|javascript:|onerror=|onload=',
        'path_traversal': r'\.\./|\.\.',
        'command_injection': r';|\||&&|`',
        'brute_force': r'failed (login|password|authentication)',
    }
    
    # Suspicious commands
    SUSPICIOUS_COMMANDS = [
        'wget', 'curl', 'nc', 'netcat', 'rm -rf', 'chmod 777',
        '/bin/bash', '/bin/sh', 'python -c', 'perl -e', 'base64'
    ]
    
    def __init__(self):
        self.logs = []
        self.parsed_logs = []
        self.statistics = {}
    
    def load_logs(self, log_content: str) -> int:
        """Load log content (file content or list of lines)"""
        if isinstance(log_content, str):
            self.logs = log_content.strip().split('\n')
        else:
            self.logs = log_content
        
        return len(self.logs)
    
    def parse_logs(self) -> List[Dict]:
        """Parse logs into structured format"""
        self.parsed_logs = []
        
        for line_num, line in enumerate(self.logs, 1):
            parsed_entry = {
                'line_number': line_num,
                'raw': line,
                'timestamp': self._extract_timestamp(line),
                'type': self._identify_log_type(line),
                'severity': self._assess_severity(line),
                'details': {}
            }
            
            # Extract specific details based on type
            if parsed_entry['type']:
                parsed_entry['details'] = self._extract_details(line, parsed_entry['type'])
            
            self.parsed_logs.append(parsed_entry)
        
        return self.parsed_logs
    
    def _extract_timestamp(self, log_line: str) -> str:
        """Extract timestamp from log line"""
        # Common timestamp patterns
        patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\w{3} \d{2} \d{2}:\d{2}:\d{2}',
            r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, log_line)
            if match:
                return match.group(0)
        
        return "Unknown"
    
    def _identify_log_type(self, log_line: str) -> str:
        """Identify the type of log entry"""
        for log_type, pattern in self.LOG_PATTERNS.items():
            if re.search(pattern, log_line, re.IGNORECASE):
                return log_type
        return "unknown"
    
    def _assess_severity(self, log_line: str) -> str:
        """Assess severity of log entry"""
        log_lower = log_line.lower()
        
        # Critical keywords
        if any(word in log_lower for word in ['critical', 'fatal', 'panic', 'emergency']):
            return "CRITICAL"
        
        # High severity
        if any(word in log_lower for word in ['error', 'failed', 'denied', 'blocked', 'attack']):
            return "HIGH"
        
        # Medium severity
        if any(word in log_lower for word in ['warning', 'warn', 'suspicious', 'unauthorized']):
            return "MEDIUM"
        
        # Low severity
        if any(word in log_lower for word in ['info', 'notice', 'accepted', 'success']):
            return "LOW"
        
        return "UNKNOWN"
    
    def _extract_details(self, log_line: str, log_type: str) -> Dict:
        """Extract specific details based on log type"""
        pattern = self.LOG_PATTERNS.get(log_type, '')
        match = re.search(pattern, log_line, re.IGNORECASE)
        
        details = {}
        
        if match:
            if log_type == 'ssh_failed':
                details = {'username': match.group(1), 'ip': match.group(2)}
            elif log_type == 'ssh_accepted':
                details = {'username': match.group(1), 'ip': match.group(2)}
            elif log_type == 'sudo':
                details = {
                    'user': match.group(1),
                    'tty': match.group(2),
                    'pwd': match.group(3),
                    'target_user': match.group(4),
                    'command': match.group(5)
                }
            elif log_type == 'apache_access':
                details = {
                    'ip': match.group(1),
                    'timestamp': match.group(2),
                    'request': match.group(3),
                    'status': match.group(4),
                    'size': match.group(5)
                }
            elif log_type == 'firewall_block':
                details = {
                    'src_ip': match.group(1),
                    'dst_ip': match.group(2),
                    'protocol': match.group(3),
                    'port': match.group(4)
                }
        
        return details
    
    def detect_suspicious_activity(self) -> List[Dict]:
        """Detect suspicious patterns in logs"""
        suspicious_events = []
        
        for entry in self.parsed_logs:
            findings = []
            
            # Check for suspicious patterns
            for pattern_name, pattern in self.SUSPICIOUS_PATTERNS.items():
                if re.search(pattern, entry['raw'], re.IGNORECASE):
                    findings.append(f"Potential {pattern_name.replace('_', ' ')}")
            
            # Check for suspicious commands in sudo logs
            if entry['type'] == 'sudo' and 'command' in entry['details']:
                command = entry['details']['command']
                for sus_cmd in self.SUSPICIOUS_COMMANDS:
                    if sus_cmd in command.lower():
                        findings.append(f"Suspicious command: {sus_cmd}")
            
            if findings:
                suspicious_events.append({
                    'line_number': entry['line_number'],
                    'type': entry['type'],
                    'severity': entry['severity'],
                    'findings': findings,
                    'raw': entry['raw'][:100] + '...' if len(entry['raw']) > 100 else entry['raw']
                })
        
        return suspicious_events
    
    def analyze_failed_logins(self) -> Dict:
        """Analyze failed login attempts"""
        failed_logins = [
            entry for entry in self.parsed_logs 
            if entry['type'] in ['ssh_failed', 'login_attempt']
        ]
        
        if not failed_logins:
            return {'count': 0, 'unique_ips': 0, 'unique_users': 0, 'top_attackers': []}
        
        # Extract IPs and usernames
        ips = []
        usernames = []
        
        for entry in failed_logins:
            if 'ip' in entry['details']:
                ips.append(entry['details']['ip'])
            if 'username' in entry['details']:
                usernames.append(entry['details']['username'])
        
        ip_counter = Counter(ips)
        user_counter = Counter(usernames)
        
        return {
            'count': len(failed_logins),
            'unique_ips': len(set(ips)),
            'unique_users': len(set(usernames)),
            'top_attackers': ip_counter.most_common(5),
            'top_targeted_users': user_counter.most_common(5),
            'brute_force_candidates': [ip for ip, count in ip_counter.items() if count > 5]
        }
    
    def analyze_sudo_usage(self) -> Dict:
        """Analyze sudo command usage"""
        sudo_logs = [entry for entry in self.parsed_logs if entry['type'] == 'sudo']
        
        if not sudo_logs:
            return {'count': 0, 'users': {}, 'commands': []}
        
        users = defaultdict(int)
        commands = []
        
        for entry in sudo_logs:
            if 'user' in entry['details']:
                users[entry['details']['user']] += 1
            if 'command' in entry['details']:
                commands.append(entry['details']['command'])
        
        return {
            'count': len(sudo_logs),
            'users': dict(users),
            'unique_commands': len(set(commands)),
            'top_commands': Counter(commands).most_common(10)
        }
    
    def analyze_firewall_blocks(self) -> Dict:
        """Analyze firewall block events"""
        firewall_logs = [entry for entry in self.parsed_logs if entry['type'] == 'firewall_block']
        
        if not firewall_logs:
            return {'count': 0, 'blocked_ips': [], 'targeted_ports': []}
        
        blocked_ips = []
        targeted_ports = []
        
        for entry in firewall_logs:
            if 'src_ip' in entry['details']:
                blocked_ips.append(entry['details']['src_ip'])
            if 'port' in entry['details']:
                targeted_ports.append(entry['details']['port'])
        
        return {
            'count': len(firewall_logs),
            'unique_ips': len(set(blocked_ips)),
            'top_blocked_ips': Counter(blocked_ips).most_common(10),
            'targeted_ports': Counter(targeted_ports).most_common(10)
        }
    
    def generate_statistics(self) -> Dict:
        """Generate comprehensive log statistics"""
        if not self.parsed_logs:
            self.parse_logs()
        
        # Count by type
        type_counter = Counter(entry['type'] for entry in self.parsed_logs)
        
        # Count by severity
        severity_counter = Counter(entry['severity'] for entry in self.parsed_logs)
        
        # Detect anomalies
        suspicious = self.detect_suspicious_activity()
        
        self.statistics = {
            'total_logs': len(self.parsed_logs),
            'by_type': dict(type_counter),
            'by_severity': dict(severity_counter),
            'suspicious_events': len(suspicious),
            'failed_logins': self.analyze_failed_logins(),
            'sudo_usage': self.analyze_sudo_usage(),
            'firewall_blocks': self.analyze_firewall_blocks()
        }
        
        return self.statistics
    
    def generate_report(self) -> str:
        """Generate formatted analysis report"""
        if not self.statistics:
            self.generate_statistics()
        
        report = []
        report.append("=" * 70)
        report.append("SECURITY LOG ANALYSIS REPORT")
        report.append("=" * 70)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Total Log Entries: {self.statistics['total_logs']}\n")
        
        # Severity breakdown
        report.append("📊 SEVERITY BREAKDOWN:")
        report.append("-" * 70)
        for severity, count in sorted(self.statistics['by_severity'].items()):
            percentage = (count / self.statistics['total_logs']) * 100
            report.append(f"  {severity:10s}: {count:5d} ({percentage:5.1f}%)")
        report.append("")
        
        # Suspicious events
        report.append(f"⚠️  SUSPICIOUS EVENTS: {self.statistics['suspicious_events']}")
        report.append("-" * 70)
        
        # Failed logins
        failed = self.statistics['failed_logins']
        if failed['count'] > 0:
            report.append(f"\n🔐 FAILED LOGIN ANALYSIS:")
            report.append(f"  Total Failed Attempts: {failed['count']}")
            report.append(f"  Unique IP Addresses: {failed['unique_ips']}")
            report.append(f"  Unique Usernames: {failed['unique_users']}")
            
            if failed['brute_force_candidates']:
                report.append(f"\n  🚨 Potential Brute Force Attacks:")
                for ip in failed['brute_force_candidates']:
                    report.append(f"    - {ip}")
        
        # Sudo usage
        sudo = self.statistics['sudo_usage']
        if sudo['count'] > 0:
            report.append(f"\n🔧 SUDO USAGE:")
            report.append(f"  Total Sudo Commands: {sudo['count']}")
            report.append(f"  Unique Commands: {sudo['unique_commands']}")
        
        # Firewall blocks
        firewall = self.statistics['firewall_blocks']
        if firewall['count'] > 0:
            report.append(f"\n🛡️  FIREWALL BLOCKS:")
            report.append(f"  Total Blocked Connections: {firewall['count']}")
            report.append(f"  Unique Blocked IPs: {firewall['unique_ips']}")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)


def main():
    """Test log analyzer"""
    
    # Sample log data
    sample_logs = """
2024-12-08 10:15:23 Failed password for root from 192.168.1.100
2024-12-08 10:15:25 Failed password for root from 192.168.1.100
2024-12-08 10:15:27 Failed password for admin from 192.168.1.100
2024-12-08 10:20:45 Accepted password for john from 10.0.0.50
2024-12-08 11:30:00 sudo: alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/cat /etc/shadow
2024-12-08 12:45:10 BLOCK IN=eth0 SRC=203.0.113.45 DST=192.168.1.1 PROTO=TCP DPT=22
2024-12-08 13:00:00 Failed password for test from 198.51.100.20
192.168.1.50 - - [08/Dec/2024:14:20:30] "GET /admin' OR '1'='1 HTTP/1.1" 403 1234
"""
    
    analyzer = LogAnalyzer()
    
    print("=" * 70)
    print("LOG ANALYZER - TEST")
    print("=" * 70)
    
    # Load and parse logs
    count = analyzer.load_logs(sample_logs)
    print(f"\n📁 Loaded {count} log entries")
    
    analyzer.parse_logs()
    print(f"✅ Parsed {len(analyzer.parsed_logs)} entries")
    
    # Detect suspicious activity
    suspicious = analyzer.detect_suspicious_activity()
    print(f"\n⚠️  Found {len(suspicious)} suspicious events")
    
    # Generate report
    print("\n" + analyzer.generate_report())


if __name__ == "__main__":
    main()