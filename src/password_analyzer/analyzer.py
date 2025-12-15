"""
Password Strength Analyzer Module
Analyzes password strength and provides security recommendations
"""

import re
import hashlib
import math
from typing import Dict, List, Tuple


class PasswordAnalyzer:
    """Analyzes password strength and provides recommendations"""
    
    # Common weak passwords (subset)
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'shadow', '123123', '654321', 'superman'
    }
    
    def __init__(self):
        self.analysis_result = {}
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy (randomness)"""
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return round(entropy, 2)
    
    def check_patterns(self, password: str) -> List[str]:
        """Check for common patterns in password"""
        issues = []
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            issues.append("Contains repeated characters (e.g., 'aaa', '111')")
        
        # Check for sequential characters
        sequences = ['abc', '123', 'qwe', 'asd', 'zxc']
        for seq in sequences:
            if seq in password.lower():
                issues.append(f"Contains sequential pattern: '{seq}'")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '12345']
        for pattern in keyboard_patterns:
            if pattern in password.lower():
                issues.append(f"Contains keyboard pattern: '{pattern}'")
        
        # Check for common words
        if any(word in password.lower() for word in ['password', 'admin', 'user', 'login']):
            issues.append("Contains common security-related words")
        
        return issues
    
    def analyze_complexity(self, password: str) -> Dict[str, bool]:
        """Analyze password complexity requirements"""
        return {
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_numbers': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'min_length': len(password) >= 8,
            'recommended_length': len(password) >= 12
        }
    
    def calculate_score(self, password: str) -> Tuple[int, str]:
        """Calculate overall password score (0-100)"""
        score = 0
        
        # Length scoring (max 30 points)
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        elif length >= 6:
            score += 10
        else:
            score += 5
        
        # Complexity scoring (max 40 points)
        complexity = self.analyze_complexity(password)
        if complexity['has_lowercase']:
            score += 10
        if complexity['has_uppercase']:
            score += 10
        if complexity['has_numbers']:
            score += 10
        if complexity['has_special']:
            score += 10
        
        # Entropy scoring (max 20 points)
        entropy = self.calculate_entropy(password)
        if entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 15
        elif entropy >= 28:
            score += 10
        else:
            score += 5
        
        # Pattern detection (max -30 points)
        patterns = self.check_patterns(password)
        score -= len(patterns) * 10
        
        # Common password check (-50 points)
        if password.lower() in self.COMMON_PASSWORDS:
            score -= 50
        
        # Ensure score is between 0 and 100
        score = max(0, min(100, score))
        
        # Determine strength level
        if score >= 80:
            strength = "Very Strong"
        elif score >= 60:
            strength = "Strong"
        elif score >= 40:
            strength = "Moderate"
        elif score >= 20:
            strength = "Weak"
        else:
            strength = "Very Weak"
        
        return score, strength
    
    def generate_recommendations(self, password: str) -> List[str]:
        """Generate improvement recommendations"""
        recommendations = []
        complexity = self.analyze_complexity(password)
        patterns = self.check_patterns(password)
        
        if not complexity['recommended_length']:
            recommendations.append("🔒 Increase length to at least 12 characters")
        
        if not complexity['has_uppercase']:
            recommendations.append("🔠 Add uppercase letters (A-Z)")
        
        if not complexity['has_lowercase']:
            recommendations.append("🔡 Add lowercase letters (a-z)")
        
        if not complexity['has_numbers']:
            recommendations.append("🔢 Add numbers (0-9)")
        
        if not complexity['has_special']:
            recommendations.append("✨ Add special characters (!@#$%^&*)")
        
        if patterns:
            recommendations.append("⚠️ Avoid common patterns and sequences")
        
        if password.lower() in self.COMMON_PASSWORDS:
            recommendations.append("🚫 This is a commonly used password - choose something unique")
        
        if not recommendations:
            recommendations.append("✅ Your password meets strong security standards!")
        
        return recommendations
    
    def analyze(self, password: str) -> Dict:
        """Perform complete password analysis"""
        if not password:
            return {
                'error': 'Password cannot be empty',
                'score': 0,
                'strength': 'Invalid'
            }
        
        score, strength = self.calculate_score(password)
        complexity = self.analyze_complexity(password)
        entropy = self.calculate_entropy(password)
        patterns = self.check_patterns(password)
        recommendations = self.generate_recommendations(password)
        
        # Calculate time to crack (simplified estimation)
        attempts_per_second = 1_000_000_000  # 1 billion attempts/sec
        charset_size = 0
        if complexity['has_lowercase']:
            charset_size += 26
        if complexity['has_uppercase']:
            charset_size += 26
        if complexity['has_numbers']:
            charset_size += 10
        if complexity['has_special']:
            charset_size += 32
        
        if charset_size > 0:
            total_combinations = charset_size ** len(password)
            seconds_to_crack = total_combinations / (2 * attempts_per_second)
            time_to_crack = self._format_time(seconds_to_crack)
        else:
            time_to_crack = "Instantly"
        
        return {
            'password_length': len(password),
            'score': score,
            'strength': strength,
            'entropy': entropy,
            'complexity': complexity,
            'patterns_found': patterns,
            'recommendations': recommendations,
            'estimated_crack_time': time_to_crack,
            'is_common': password.lower() in self.COMMON_PASSWORDS
        }
    
    def _format_time(self, seconds: float) -> str:
        """Format time in human-readable format"""
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} years"
        else:
            return "Centuries"


def main():
    """Test the password analyzer"""
    analyzer = PasswordAnalyzer()
    
    test_passwords = [
        "password",
        "Password123",
        "P@ssw0rd!2024",
        "MyS3cur3P@ssw0rd!",
        "aB3$xK9#mP2@qL5"
    ]
    
    print("=" * 60)
    print("PASSWORD STRENGTH ANALYZER - TEST RESULTS")
    print("=" * 60)
    
    for pwd in test_passwords:
        result = analyzer.analyze(pwd)
        print(f"\nPassword: {'*' * len(pwd)}")
        print(f"Score: {result['score']}/100")
        print(f"Strength: {result['strength']}")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Crack Time: {result['estimated_crack_time']}")
        print("\nRecommendations:")
        for rec in result['recommendations']:
            print(f"  • {rec}")
        print("-" * 60)


if __name__ == "__main__":
    main()