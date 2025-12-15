"""
Configuration file for SecureGuard
Contains settings and constants
"""

import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent

# Scanner Configuration
PORT_SCANNER_CONFIG = {
    'timeout': 1.0,  # Timeout for each port check in seconds
    'max_workers': 100,  # Maximum number of concurrent threads
    'default_ports': [
        # Common ports to scan
        21,    # FTP
        22,    # SSH
        23,    # Telnet
        25,    # SMTP
        53,    # DNS
        80,    # HTTP
        110,   # POP3
        143,   # IMAP
        443,   # HTTPS
        445,   # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP-Proxy
        8443,  # HTTPS-Alt
        27017  # MongoDB
    ]
}

# Password Analyzer Configuration
PASSWORD_CONFIG = {
    'min_length': 8,  # Minimum password length
    'recommended_length': 12,  # Recommended password length
    'entropy_threshold_weak': 28,  # Entropy threshold for weak passwords
    'entropy_threshold_moderate': 40,  # Entropy threshold for moderate passwords
    'entropy_threshold_strong': 60,  # Entropy threshold for strong passwords
    
    # Password scoring weights
    'score_weights': {
        'length': 30,      # Maximum points for length
        'complexity': 40,  # Maximum points for complexity
        'entropy': 20,     # Maximum points for entropy
        'patterns': -30    # Penalty for patterns
    }
}

# URL Detector Configuration
URL_CONFIG = {
    'max_url_length': 75,  # URLs longer than this are suspicious
    
    # Suspicious top-level domains
    'suspicious_tlds': [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs often used in phishing
        '.top', '.xyz', '.club', '.work',
        '.click', '.link', '.zip'
    ],
    
    # Trusted domains for brand impersonation detection
    'trusted_domains': [
        'google.com', 'microsoft.com', 'apple.com', 
        'amazon.com', 'facebook.com', 'twitter.com',
        'github.com', 'linkedin.com', 'instagram.com',
        'paypal.com', 'ebay.com', 'netflix.com'
    ],
    
    # Phishing keywords to detect
    'phishing_keywords': [
        'verify', 'account', 'suspended', 'login', 'update',
        'confirm', 'secure', 'banking', 'alert', 'urgent',
        'click-here', 'winner', 'prize', 'free', 'offer',
        'reset', 'expired', 'locked', 'validate', 'suspend'
    ],
    
    # Risk scoring thresholds
    'risk_thresholds': {
        'safe': 30,      # < 30 is safe
        'low': 50,       # 30-49 is low risk
        'medium': 70,    # 50-69 is medium risk
        'high': 100      # 70+ is high/critical risk
    }
}

# Log Analyzer Configuration
LOG_CONFIG = {
    'max_logs_to_display': 100,  # Maximum number of log entries to display
    'brute_force_threshold': 5,   # Number of failed attempts to consider brute force
    'time_window_minutes': 60,    # Time window for correlation
    
    # Log patterns to detect
    'patterns': {
        'ssh_failed': r'Failed password for (\w+) from ([\d.]+)',
        'ssh_accepted': r'Accepted password for (\w+) from ([\d.]+)',
        'sudo': r'sudo:\s+(\w+) : TTY=(\w+) ; PWD=([^;]+) ; USER=(\w+) ; COMMAND=(.+)',
        'apache_error': r'\[([\w\s:]+)\] \[(\w+)\] (.+)',
        'apache_access': r'([\d.]+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)',
        'firewall_block': r'BLOCK.*SRC=([\d.]+).*DST=([\d.]+).*PROTO=(\w+).*DPT=(\d+)',
        'login_attempt': r'authentication failure.*user=(\w+).*rhost=([\d.]+)'
    },
    
    # Suspicious commands to flag
    'suspicious_commands': [
        'wget', 'curl', 'nc', 'netcat', 'rm -rf', 
        'chmod 777', '/bin/bash', '/bin/sh', 
        'python -c', 'perl -e', 'base64', 'eval',
        'powershell', 'cmd.exe'
    ],
    
    # High risk ports
    'high_risk_ports': [21, 23, 445, 3389, 5900],  # FTP, Telnet, SMB, RDP, VNC
    
    # Medium risk ports
    'medium_risk_ports': [22, 3306, 5432, 6379, 27017]  # SSH, DBs, Redis, MongoDB
}

# Output Configuration
OUTPUT_CONFIG = {
    'use_colors': True,   # Enable colored output
    'verbose': False,     # Verbose output mode
    'save_reports': False,  # Save reports to files
    'report_directory': BASE_DIR / 'reports',  # Directory for saved reports
    
    # Color scheme (used with colorama)
    'colors': {
        'success': 'GREEN',
        'warning': 'YELLOW',
        'error': 'RED',
        'info': 'CYAN',
        'highlight': 'MAGENTA'
    }
}

# Security Configuration
SECURITY_CONFIG = {
    # Rate limiting for scans (to prevent abuse)
    'max_targets_per_session': 10,
    'max_ports_per_scan': 10000,
    
    # Warnings and disclaimers
    'require_confirmation': True,  # Require confirmation for scans
    'show_legal_warning': True,    # Show legal warning on startup
    
    # Legal disclaimer text
    'legal_warning': """
    ⚠️  LEGAL DISCLAIMER ⚠️
    
    This tool is for authorized security testing only.
    
    - Only scan systems you own or have explicit permission to test
    - Unauthorized scanning may be illegal in your jurisdiction
    - Use responsibly and ethically
    
    By continuing, you confirm you have proper authorization.
    """
}

# Application Metadata
APP_CONFIG = {
    'name': 'SecureGuard',
    'version': '1.0.0',
    'description': 'Cybersecurity Analysis Platform',
    'authors': ['Team Member 1', 'Team Member 2'],
    'license': 'MIT',
    'repository': 'https://github.com/YOUR-USERNAME/securityguard-tool'
}

# Feature flags (enable/disable features)
FEATURES = {
    'password_analyzer': True,
    'port_scanner': True,
    'url_detector': True,
    'log_analyzer': True,
    'save_reports': False,  # Save reports to files
    'export_json': False,   # Export results as JSON
    'export_csv': False     # Export results as CSV
}

# Create reports directory if saving is enabled
if OUTPUT_CONFIG['save_reports']:
    OUTPUT_CONFIG['report_directory'].mkdir(exist_ok=True)


# Helper function to get configuration value
def get_config(section, key, default=None):
    """
    Get a configuration value
    
    Args:
        section (str): Configuration section name
        key (str): Configuration key
        default: Default value if not found
    
    Returns:
        Configuration value or default
    """
    config_sections = {
        'port_scanner': PORT_SCANNER_CONFIG,
        'password': PASSWORD_CONFIG,
        'url': URL_CONFIG,
        'log': LOG_CONFIG,
        'output': OUTPUT_CONFIG,
        'security': SECURITY_CONFIG,
        'app': APP_CONFIG,
        'features': FEATURES
    }
    
    section_config = config_sections.get(section, {})
    return section_config.get(key, default)


# Helper function to display all configuration
def display_config():
    """Display all configuration settings"""
    print("=" * 70)
    print("SecureGuard Configuration")
    print("=" * 70)
    
    print("\n[Application]")
    for key, value in APP_CONFIG.items():
        print(f"  {key}: {value}")
    
    print("\n[Features]")
    for key, value in FEATURES.items():
        status = "Enabled" if value else "Disabled"
        print(f"  {key}: {status}")
    
    print("\n[Port Scanner]")
    print(f"  Timeout: {PORT_SCANNER_CONFIG['timeout']}s")
    print(f"  Max Workers: {PORT_SCANNER_CONFIG['max_workers']}")
    print(f"  Default Ports: {len(PORT_SCANNER_CONFIG['default_ports'])} ports")
    
    print("\n[Password Analyzer]")
    print(f"  Min Length: {PASSWORD_CONFIG['min_length']}")
    print(f"  Recommended Length: {PASSWORD_CONFIG['recommended_length']}")
    
    print("\n[URL Detector]")
    print(f"  Max URL Length: {URL_CONFIG['max_url_length']}")
    print(f"  Suspicious TLDs: {len(URL_CONFIG['suspicious_tlds'])}")
    print(f"  Trusted Domains: {len(URL_CONFIG['trusted_domains'])}")
    
    print("\n[Log Analyzer]")
    print(f"  Brute Force Threshold: {LOG_CONFIG['brute_force_threshold']}")
    print(f"  Time Window: {LOG_CONFIG['time_window_minutes']} minutes")
    
    print("\n[Output]")
    print(f"  Colors: {'Enabled' if OUTPUT_CONFIG['use_colors'] else 'Disabled'}")
    print(f"  Verbose: {'Enabled' if OUTPUT_CONFIG['verbose'] else 'Disabled'}")
    print(f"  Save Reports: {'Enabled' if OUTPUT_CONFIG['save_reports'] else 'Disabled'}")
    
    print("=" * 70)


if __name__ == "__main__":
    # Display configuration when run directly
    display_config()