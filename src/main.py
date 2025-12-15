#!/usr/bin/env python3
"""
SecureGuard - Cybersecurity Analysis Platform
Main application entry point
"""

import sys
import argparse
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from password_analyzer.analyzer import PasswordAnalyzer
from port_scanner.scanner import PortScanner
from url_detector.detector import URLDetector
from log_analyzer.parser import LogAnalyzer

from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)


class SecureGuardCLI:
    """Main CLI interface for SecureGuard"""
    
    def __init__(self):
        self.banner = """
╔═══════════════════════════════════════════════════════════════╗
║                        SecureGuard                            ║
║              Cybersecurity Analysis Platform                  ║
╚═══════════════════════════════════════════════════════════════╝
"""
    
    def print_banner(self):
        """Print application banner"""
        print(Fore.CYAN + self.banner)
    
    def analyze_password(self, password: str):
        """Analyze password strength"""
        print(Fore.YELLOW + "\n🔐 PASSWORD STRENGTH ANALYZER")
        print("=" * 70)
        
        analyzer = PasswordAnalyzer()
        result = analyzer.analyze(password)
        
        if 'error' in result:
            print(Fore.RED + f"❌ Error: {result['error']}")
            return
        
        # Display basic results
        print(f"\n{Fore.CYAN}Password Length: {result['password_length']} characters")
        
        # Color code based on strength
        strength_color = {
            'Very Strong': Fore.GREEN,
            'Strong': Fore.GREEN,
            'Moderate': Fore.YELLOW,
            'Weak': Fore.RED,
            'Very Weak': Fore.RED
        }
        
        color = strength_color.get(result['strength'], Fore.WHITE)
        print(f"{color}Strength: {result['strength']} ({result['score']}/100)")
        print(f"{Fore.CYAN}Entropy: {result['entropy']} bits")
        print(f"{Fore.CYAN}Estimated Crack Time: {result['estimated_crack_time']}")
        
        # Display complexity
        print(f"\n{Fore.YELLOW}Complexity Requirements:")
        complexity = result['complexity']
        checks = [
            ("Lowercase letters", complexity['has_lowercase']),
            ("Uppercase letters", complexity['has_uppercase']),
            ("Numbers", complexity['has_numbers']),
            ("Special characters", complexity['has_special']),
            ("Min length (8+)", complexity['min_length']),
            ("Recommended length (12+)", complexity['recommended_length'])
        ]
        
        for check_name, passed in checks:
            icon = "✅" if passed else "❌"
            print(f"  {icon} {check_name}")
        
        # Display patterns found
        if result['patterns_found']:
            print(f"\n{Fore.RED}⚠️  Patterns Detected:")
            for pattern in result['patterns_found']:
                print(f"  • {pattern}")
        
        # Display recommendations
        if result['recommendations']:
            print(f"\n{Fore.YELLOW}💡 Recommendations:")
            for rec in result['recommendations']:
                print(f"  {rec}")
        
        # Common password warning
        if result['is_common']:
            print(f"\n{Fore.RED}🚨 WARNING: This is a commonly used password!")
            print(f"{Fore.RED}   It appears in known password databases and should NOT be used.")
    
    def scan_ports(self, target: str, port_range: str = "common"):
        """Scan network ports"""
        print(Fore.YELLOW + "\n🌐 NETWORK PORT SCANNER")
        print("=" * 70)
        
        scanner = PortScanner(timeout=1.0)
        
        try:
            if port_range == "common":
                results = scanner.scan_common_ports(target)
            else:
                start, end = map(int, port_range.split('-'))
                results = scanner.scan_port_range(target, start, end)
            
            # Display report
            print(scanner.generate_report())
            
            # Security summary
            summary = scanner.get_security_summary()
            print(f"\n{Fore.YELLOW}🛡️  SECURITY SUMMARY:")
            print("=" * 70)
            
            risk_colors = {
                'HIGH': Fore.RED,
                'MEDIUM': Fore.YELLOW,
                'LOW': Fore.GREEN,
                'Unknown': Fore.WHITE
            }
            
            risk_color = risk_colors.get(summary['risk_level'], Fore.WHITE)
            print(f"{risk_color}Risk Level: {summary['risk_level']}")
            print(f"{Fore.CYAN}Open Ports Found: {summary['open_ports_count']}")
            print(f"{Fore.CYAN}High-Risk Ports: {summary['high_risk_ports']}")
            print(f"{Fore.CYAN}Medium-Risk Ports: {summary['medium_risk_ports']}")
            
            if summary['issues']:
                print(f"\n{Fore.RED}⚠️  Security Issues:")
                for issue in summary['issues']:
                    print(f"  {issue}")
            else:
                print(f"\n{Fore.GREEN}✅ No major security issues detected")
            
            # Recommendations
            if summary['high_risk_ports'] > 0:
                print(f"\n{Fore.YELLOW}💡 Recommendations:")
                print(f"  • Review and close unnecessary high-risk ports")
                print(f"  • Ensure services are properly secured and updated")
                print(f"  • Use firewall rules to restrict access")
                print(f"  • Enable logging and monitoring for open ports")
        
        except ValueError as e:
            print(f"{Fore.RED}❌ Error: Invalid port range format. Use 'common' or 'start-end' (e.g., 1-1000)")
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}")
    
    def check_url(self, url: str):
        """Check URL for malicious content"""
        print(Fore.YELLOW + "\n🔗 MALICIOUS URL DETECTOR")
        print("=" * 70)
        
        detector = URLDetector()
        result = detector.analyze(url)
        
        if 'error' in result:
            print(Fore.RED + f"❌ Error: {result['error']}")
            return
        
        # Display results
        print(f"\n{Fore.CYAN}URL: {result['url']}")
        print(f"{Fore.CYAN}Domain: {result['parsed']['domain']}")
        print(f"{Fore.CYAN}Scheme: {result['parsed']['scheme']}")
        
        # Color code based on threat level
        threat_colors = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.RED,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.YELLOW,
            'SAFE': Fore.GREEN
        }
        
        color = threat_colors.get(result['threat_level'], Fore.WHITE)
        print(f"\n{color}Risk Score: {result['risk_score']}/100")
        print(f"{color}Threat Level: {result['threat_level']}")
        
        safe_icon = '🟢' if result['is_safe'] else '🔴'
        safe_text = 'Yes' if result['is_safe'] else 'NO - DO NOT VISIT'
        print(f"{safe_icon} Safe to Visit: {safe_text}")
        
        # Display warnings
        if result['warnings']:
            print(f"\n{Fore.RED}⚠️  Security Warnings:")
            for warning in result['warnings']:
                print(f"  • {warning}")
        else:
            print(f"\n{Fore.GREEN}✅ No security concerns detected")
        
        # Recommendations based on threat level
        if result['threat_level'] in ['CRITICAL', 'HIGH']:
            print(f"\n{Fore.RED}🚨 DANGER - DO NOT VISIT THIS URL!")
            print(f"{Fore.YELLOW}💡 Recommendations:")
            print(f"  • Do not click on this link")
            print(f"  • Do not enter any personal information")
            print(f"  • Report this URL if received via email/message")
            print(f"  • Warn others if you received this from someone")
        elif result['threat_level'] == 'MEDIUM':
            print(f"\n{Fore.YELLOW}⚠️  Proceed with Caution")
            print(f"{Fore.YELLOW}💡 Recommendations:")
            print(f"  • Verify the URL is legitimate before visiting")
            print(f"  • Do not enter sensitive information")
            print(f"  • Use caution when downloading files")
        elif result['threat_level'] == 'LOW':
            print(f"\n{Fore.YELLOW}💡 Minor concerns detected - stay vigilant")
        else:
            print(f"\n{Fore.GREEN}✅ URL appears safe, but always stay cautious online")
    
    def analyze_logs(self, log_file: str):
        """Analyze security logs"""
        print(Fore.YELLOW + "\n📋 LOG FILE ANALYZER")
        print("=" * 70)
        
        try:
            # Read log file
            with open(log_file, 'r') as f:
                log_content = f.read()
            
            analyzer = LogAnalyzer()
            
            # Load and parse
            count = analyzer.load_logs(log_content)
            print(f"\n{Fore.CYAN}📁 Loaded {count} log entries")
            
            analyzer.parse_logs()
            print(f"{Fore.GREEN}✅ Parsed {len(analyzer.parsed_logs)} entries successfully")
            
            # Detect suspicious activity
            suspicious = analyzer.detect_suspicious_activity()
            
            if suspicious:
                print(f"{Fore.RED}⚠️  Found {len(suspicious)} suspicious events")
            else:
                print(f"{Fore.GREEN}✅ No suspicious events detected")
            
            # Generate and display report
            print("\n" + analyzer.generate_report())
            
            # Display suspicious events in detail
            if suspicious:
                print(f"\n{Fore.RED}🚨 DETAILED SUSPICIOUS EVENTS:")
                print("=" * 70)
                for i, event in enumerate(suspicious[:10], 1):  # Show first 10
                    print(f"\n{Fore.YELLOW}[{i}] Line {event['line_number']}:")
                    print(f"    Type: {event['type']}")
                    print(f"    Severity: {event['severity']}")
                    print(f"    Findings:")
                    for finding in event['findings']:
                        print(f"      • {finding}")
                    print(f"    Log: {event['raw'][:80]}...")
                
                if len(suspicious) > 10:
                    print(f"\n{Fore.YELLOW}... and {len(suspicious) - 10} more suspicious events")
            
            # Recommendations based on findings
            stats = analyzer.generate_statistics()
            print(f"\n{Fore.YELLOW}💡 Security Recommendations:")
            print("=" * 70)
            
            failed = stats['failed_logins']
            if failed['count'] > 0:
                print(f"{Fore.YELLOW}• Failed Logins Detected:")
                print(f"  - Review and investigate {failed['count']} failed login attempts")
                if failed['brute_force_candidates']:
                    print(f"  - URGENT: Block IPs attempting brute force: {', '.join(failed['brute_force_candidates'])}")
                print(f"  - Consider implementing rate limiting or fail2ban")
            
            sudo = stats['sudo_usage']
            if sudo['count'] > 0:
                print(f"{Fore.YELLOW}• Sudo Activity:")
                print(f"  - Review {sudo['count']} sudo commands for unauthorized access")
                print(f"  - Ensure sudo usage is properly logged and monitored")
            
            firewall = stats['firewall_blocks']
            if firewall['count'] > 0:
                print(f"{Fore.YELLOW}• Firewall Blocks:")
                print(f"  - {firewall['count']} connection attempts were blocked")
                print(f"  - Review blocked IPs for potential threats")
            
            if stats['suspicious_events'] > 0:
                print(f"{Fore.RED}• CRITICAL: Investigate all {stats['suspicious_events']} suspicious events immediately")
                print(f"  - Look for patterns in attack attempts")
                print(f"  - Check if any attacks were successful")
                print(f"  - Update security policies based on findings")
        
        except FileNotFoundError:
            print(f"{Fore.RED}❌ Error: File '{log_file}' not found")
            print(f"{Fore.YELLOW}   Make sure the file path is correct and the file exists")
        except PermissionError:
            print(f"{Fore.RED}❌ Error: Permission denied to read '{log_file}'")
            print(f"{Fore.YELLOW}   Try running with elevated privileges (sudo)")
        except Exception as e:
            print(f"{Fore.RED}❌ Error: {e}")
    
    def run_interactive(self):
        """Run in interactive mode"""
        self.print_banner()
        
        while True:
            print(f"\n{Fore.CYAN}╔════════════════════════════════════════╗")
            print(f"{Fore.CYAN}║         Available Features             ║")
            print(f"{Fore.CYAN}╚════════════════════════════════════════╝")
            print(f"{Fore.GREEN}  1. 🔐 Password Strength Analyzer")
            print(f"{Fore.GREEN}  2. 🌐 Network Port Scanner")
            print(f"{Fore.GREEN}  3. 🔗 Malicious URL Detector")
            print(f"{Fore.GREEN}  4. 📋 Log File Analyzer")
            print(f"{Fore.RED}  5. 🚪 Exit")
            
            choice = input(f"\n{Fore.YELLOW}Select a feature (1-5): {Style.RESET_ALL}").strip()
            
            if choice == '1':
                print(f"\n{Fore.CYAN}═══ Password Strength Analyzer ═══")
                password = input(f"{Fore.CYAN}Enter password to analyze: {Style.RESET_ALL}")
                if password:
                    self.analyze_password(password)
                else:
                    print(f"{Fore.RED}Error: Password cannot be empty")
            
            elif choice == '2':
                print(f"\n{Fore.CYAN}═══ Network Port Scanner ═══")
                target = input(f"{Fore.CYAN}Enter target IP/hostname: {Style.RESET_ALL}")
                if target:
                    scan_type = input(f"{Fore.CYAN}Scan type (common/custom) [common]: {Style.RESET_ALL}").lower() or "common"
                    port_range = "common"
                    if scan_type == "custom":
                        port_range = input(f"{Fore.CYAN}Enter port range (e.g., 1-1000): {Style.RESET_ALL}")
                    self.scan_ports(target, port_range)
                else:
                    print(f"{Fore.RED}Error: Target cannot be empty")
            
            elif choice == '3':
                print(f"\n{Fore.CYAN}═══ Malicious URL Detector ═══")
                url = input(f"{Fore.CYAN}Enter URL to check: {Style.RESET_ALL}")
                if url:
                    self.check_url(url)
                else:
                    print(f"{Fore.RED}Error: URL cannot be empty")
            
            elif choice == '4':
                print(f"\n{Fore.CYAN}═══ Log File Analyzer ═══")
                log_file = input(f"{Fore.CYAN}Enter log file path: {Style.RESET_ALL}")
                if log_file:
                    self.analyze_logs(log_file)
                else:
                    print(f"{Fore.RED}Error: File path cannot be empty")
            
            elif choice == '5':
                print(f"\n{Fore.GREEN}╔════════════════════════════════════════╗")
                print(f"{Fore.GREEN}║  Thank you for using SecureGuard! 🔒   ║")
                print(f"{Fore.GREEN}║         Stay secure!                   ║")
                print(f"{Fore.GREEN}╚════════════════════════════════════════╝")
                break
            
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please select 1-5.")
            
            # Ask if user wants to continue
            if choice in ['1', '2', '3', '4']:
                input(f"\n{Fore.CYAN}Press Enter to continue...{Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='SecureGuard - Cybersecurity Analysis Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode
  python main.py

  # Password analysis
  python main.py password "MyP@ssw0rd123"

  # Port scanning
  python main.py portscan 192.168.1.1 --range common
  python main.py portscan 192.168.1.1 --range 1-1000

  # URL checking
  python main.py urlcheck "https://suspicious-site.com"

  # Log analysis
  python main.py loganalysis /var/log/auth.log
        """
    )
    
    parser.add_argument('feature', nargs='?', 
                       choices=['password', 'portscan', 'urlcheck', 'loganalysis'],
                       help='Feature to use')
    parser.add_argument('input', nargs='?', help='Input for the feature')
    parser.add_argument('--range', default='common', 
                       help='Port range for scanning (e.g., common or 1-1000)')
    parser.add_argument('--version', action='version', version='SecureGuard 1.0.0')
    
    args = parser.parse_args()
    
    cli = SecureGuardCLI()
    
    # If no feature specified, run interactive mode
    if not args.feature:
        cli.run_interactive()
    else:
        cli.print_banner()
        
        # Run specific feature
        if args.feature == 'password':
            if not args.input:
                print(f"{Fore.RED}Error: Password required")
                print(f"{Fore.YELLOW}Usage: python main.py password \"YourPassword\"")
                sys.exit(1)
            cli.analyze_password(args.input)
        
        elif args.feature == 'portscan':
            if not args.input:
                print(f"{Fore.RED}Error: Target IP/hostname required")
                print(f"{Fore.YELLOW}Usage: python main.py portscan 192.168.1.1")
                sys.exit(1)
            cli.scan_ports(args.input, args.range)
        
        elif args.feature == 'urlcheck':
            if not args.input:
                print(f"{Fore.RED}Error: URL required")
                print(f"{Fore.YELLOW}Usage: python main.py urlcheck \"https://example.com\"")
                sys.exit(1)
            cli.check_url(args.input)
        
        elif args.feature == 'loganalysis':
            if not args.input:
                print(f"{Fore.RED}Error: Log file path required")
                print(f"{Fore.YELLOW}Usage: python main.py loganalysis /var/log/auth.log")
                sys.exit(1)
            cli.analyze_logs(args.input)


if __name__ == "__main__":
    main()