"""
Malicious URL Detector Module
Analyzes URLs for phishing, malware, and security threats
"""

import re
import urllib.parse
from typing import Dict, List, Tuple
import requests
from datetime import datetime


class URLDetector:
    """Detects malicious URLs using pattern analysis and heuristics"""
    
    # Known malicious TLDs
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.xyz',
        '.club', '.work', '.click', '.link', '.zip'
    ]
    
    # Legitimate domains for reference
    TRUSTED_DOMAINS = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
        'facebook.com', 'twitter.com', 'github.com', 'linkedin.com'
    ]
    
    # Suspicious keywords
    PHISHING_KEYWORDS = [
        'verify', 'account', 'suspended', 'login', 'update',
        'confirm', 'secure', 'banking', 'alert', 'urgent',
        'click-here', 'winner', 'prize', 'free', 'offer'
    ]
    
    def __init__(self):
        self.analysis_result = {}
    
    def parse_url(self, url: str) -> Dict:
        """Parse URL into components"""
        try:
            # Add scheme if missing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urllib.parse.urlparse(url)
            
            return {
                'original': url,
                'scheme': parsed.scheme,
                'domain': parsed.netloc,
                'path': parsed.path,
                'params': parsed.params,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except Exception as e:
            return {'error': str(e)}
    
    def check_url_length(self, url: str) -> Tuple[bool, str]:
        """Check if URL is suspiciously long"""
        if len(url) > 75:
            return True, f"Suspicious length: {len(url)} characters"
        return False, "Normal length"
    
    def check_ip_address(self, domain: str) -> Tuple[bool, str]:
        """Check if domain is an IP address (suspicious)"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        if re.match(ip_pattern, domain):
            return True, "Uses IP address instead of domain name"
        return False, "Uses domain name"
    
    def check_suspicious_tld(self, domain: str) -> Tuple[bool, str]:
        """Check for suspicious top-level domains"""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return True, f"Suspicious TLD: {tld}"
        return False, "Common TLD"
    
    def check_subdomain_depth(self, domain: str) -> Tuple[bool, str]:
        """Check for excessive subdomains"""
        parts = domain.split('.')
        if len(parts) > 3:
            return True, f"Deep subdomain structure: {len(parts) - 2} levels"
        return False, "Normal domain structure"
    
    def check_special_characters(self, url: str) -> Tuple[bool, List[str]]:
        """Check for suspicious special characters"""
        issues = []
        
        # Check for @ symbol (redirects)
        if '@' in url:
            issues.append("Contains '@' (possible redirect)")
        
        # Check for double slashes in path
        if url.count('//') > 1:
            issues.append("Multiple '//' (possible obfuscation)")
        
        # Check for excessive hyphens
        if url.count('-') > 4:
            issues.append(f"Many hyphens: {url.count('-')}")
        
        # Check for URL encoding
        if '%' in url:
            percent_count = url.count('%')
            if percent_count > 3:
                issues.append(f"Excessive URL encoding: {percent_count} encoded chars")
        
        return len(issues) > 0, issues
    
    def check_phishing_keywords(self, url: str) -> Tuple[bool, List[str]]:
        """Check for phishing-related keywords"""
        url_lower = url.lower()
        found_keywords = []
        
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            return True, found_keywords
        return False, []
    
    def check_https(self, scheme: str) -> Tuple[bool, str]:
        """Check if URL uses HTTPS"""
        if scheme != 'https':
            return True, "Not using HTTPS (unencrypted)"
        return False, "Uses HTTPS"
    
    def check_brand_impersonation(self, domain: str) -> Tuple[bool, List[str]]:
        """Check for brand impersonation attempts"""
        suspicious_patterns = []
        domain_lower = domain.lower()
        
        # Check for trusted domains with typos or additions
        for trusted in self.TRUSTED_DOMAINS:
            trusted_base = trusted.split('.')[0]
            
            # Check if trusted brand is in subdomain
            if trusted_base in domain_lower and not domain_lower.endswith(trusted):
                suspicious_patterns.append(f"Possible impersonation of {trusted}")
            
            # Check for common typos
            if self._levenshtein_distance(domain_lower.split('.')[0], trusted_base) == 1:
                suspicious_patterns.append(f"Typosquatting of {trusted}")
        
        return len(suspicious_patterns) > 0, suspicious_patterns
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def check_url_reputation(self, url: str) -> Tuple[str, int]:
        """Check URL against VirusTotal (simplified simulation)"""
        # This would normally call VirusTotal API
        # For demo purposes, we'll simulate based on our checks
        # In production, integrate with actual reputation services
        return "simulation", 0
    
    def calculate_risk_score(self, checks: Dict) -> Tuple[int, str]:
        """Calculate overall risk score (0-100)"""
        score = 0
        
        # Length check (5 points)
        if checks['length']['is_suspicious']:
            score += 5
        
        # IP address (15 points)
        if checks['ip_address']['is_suspicious']:
            score += 15
        
        # Suspicious TLD (10 points)
        if checks['tld']['is_suspicious']:
            score += 10
        
        # Subdomain depth (10 points)
        if checks['subdomain']['is_suspicious']:
            score += 10
        
        # Special characters (15 points)
        if checks['special_chars']['is_suspicious']:
            score += min(15, len(checks['special_chars']['issues']) * 5)
        
        # Phishing keywords (20 points)
        if checks['phishing_keywords']['is_suspicious']:
            score += min(20, len(checks['phishing_keywords']['keywords']) * 5)
        
        # No HTTPS (10 points)
        if checks['https']['is_suspicious']:
            score += 10
        
        # Brand impersonation (15 points)
        if checks['brand_impersonation']['is_suspicious']:
            score += 15
        
        # Determine threat level
        if score >= 70:
            threat_level = "CRITICAL"
        elif score >= 50:
            threat_level = "HIGH"
        elif score >= 30:
            threat_level = "MEDIUM"
        elif score >= 10:
            threat_level = "LOW"
        else:
            threat_level = "SAFE"
        
        return score, threat_level
    
    def analyze(self, url: str) -> Dict:
        """Perform comprehensive URL analysis"""
        if not url:
            return {'error': 'URL cannot be empty'}
        
        # Parse URL
        parsed = self.parse_url(url)
        if 'error' in parsed:
            return {'error': f"Invalid URL: {parsed['error']}"}
        
        # Perform all checks
        length_check = self.check_url_length(url)
        ip_check = self.check_ip_address(parsed['domain'])
        tld_check = self.check_suspicious_tld(parsed['domain'])
        subdomain_check = self.check_subdomain_depth(parsed['domain'])
        special_chars_check = self.check_special_characters(url)
        phishing_check = self.check_phishing_keywords(url)
        https_check = self.check_https(parsed['scheme'])
        brand_check = self.check_brand_impersonation(parsed['domain'])
        
        # Compile checks
        checks = {
            'length': {
                'is_suspicious': length_check[0],
                'details': length_check[1]
            },
            'ip_address': {
                'is_suspicious': ip_check[0],
                'details': ip_check[1]
            },
            'tld': {
                'is_suspicious': tld_check[0],
                'details': tld_check[1]
            },
            'subdomain': {
                'is_suspicious': subdomain_check[0],
                'details': subdomain_check[1]
            },
            'special_chars': {
                'is_suspicious': special_chars_check[0],
                'issues': special_chars_check[1]
            },
            'phishing_keywords': {
                'is_suspicious': phishing_check[0],
                'keywords': phishing_check[1]
            },
            'https': {
                'is_suspicious': https_check[0],
                'details': https_check[1]
            },
            'brand_impersonation': {
                'is_suspicious': brand_check[0],
                'patterns': brand_check[1]
            }
        }
        
        # Calculate risk score
        risk_score, threat_level = self.calculate_risk_score(checks)
        
        # Generate warnings
        warnings = []
        for check_name, check_data in checks.items():
            if check_data.get('is_suspicious'):
                if 'details' in check_data:
                    warnings.append(f"{check_name.replace('_', ' ').title()}: {check_data['details']}")
                elif 'issues' in check_data:
                    for issue in check_data['issues']:
                        warnings.append(f"{check_name.replace('_', ' ').title()}: {issue}")
                elif 'keywords' in check_data:
                    warnings.append(f"{check_name.replace('_', ' ').title()}: {', '.join(check_data['keywords'])}")
                elif 'patterns' in check_data:
                    for pattern in check_data['patterns']:
                        warnings.append(f"{check_name.replace('_', ' ').title()}: {pattern}")
        
        return {
            'url': url,
            'parsed': parsed,
            'risk_score': risk_score,
            'threat_level': threat_level,
            'checks': checks,
            'warnings': warnings,
            'is_safe': risk_score < 30,
            'timestamp': datetime.now().isoformat()
        }


def main():
    """Test URL detector"""
    detector = URLDetector()
    
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "https://secure-verify-account-login.tk/update",
        "https://g00gle.com/signin",
        "http://paypal.com-secure-login.xyz/verify"
    ]
    
    print("=" * 70)
    print("MALICIOUS URL DETECTOR - TEST RESULTS")
    print("=" * 70)
    
    for url in test_urls:
        result = detector.analyze(url)
        
        print(f"\n🔗 URL: {url}")
        print(f"🎯 Risk Score: {result['risk_score']}/100")
        print(f"⚠️  Threat Level: {result['threat_level']}")
        print(f"✅ Safe: {'Yes' if result['is_safe'] else 'No'}")
        
        if result['warnings']:
            print("\n⚠️ Warnings:")
            for warning in result['warnings']:
                print(f"  • {warning}")
        
        print("-" * 70)


if __name__ == "__main__":
    main()