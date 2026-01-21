import hashlib
import math
import requests
import time
import os
from typing import Dict, List, Tuple
import sys

class PasswordStrengthChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.animation_chars = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        self.animation_index = 0
        
    def load_common_passwords(self) -> List[str]:
        """Load a list of common passwords for dictionary check"""
        common_passwords = [
            "password", "123456", "12345678", "qwerty", "abc123", 
            "monkey", "letmein", "trustno1", "dragon", "baseball",
            "superman", "iloveyou", "starwars", "master", "hello",
            "freedom", "whatever", "qazwsx", "admin", "login", 
            "welcome", "solo", "passw0rd", "password1", "123123"
        ]
        return common_passwords
    
    def animate_loading(self, text: str):
        """Display animated loading text"""
        self.animation_index = (self.animation_index + 1) % len(self.animation_chars)
        sys.stdout.write(f"\r{self.animation_chars[self.animation_index]} {text}")
        sys.stdout.flush()
    
    def decode_animation(self, text: str, delay: float = 0.05):
        """Display text with a decoding animation"""
        decoded = ""
        for i in range(len(text)):
            decoded += text[i]
            sys.stdout.write(f"\r{decoded}")
            sys.stdout.flush()
            time.sleep(delay)
        print()
    
    def print_tree_structure(self, items: List[str], prefix: str = ""):
        """Print items in a tree-like structure"""
        for i, item in enumerate(items):
            if i == len(items) - 1:
                print(prefix + "└── " + item)
            else:
                print(prefix + "├── " + item)
    
    def calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits"""
        if not password:
            return 0
            
        # Character set size detection
        char_sets = {
            'lower': False,
            'upper': False,
            'digits': False,
            'special': False
        }
        
        for char in password:
            if char.islower():
                char_sets['lower'] = True
            elif char.isupper():
                char_sets['upper'] = True
            elif char.isdigit():
                char_sets['digits'] = True
            else:
                char_sets['special'] = True
        
        # Calculate pool size
        pool_size = 0
        if char_sets['lower']:
            pool_size += 26
        if char_sets['upper']:
            pool_size += 26
        if char_sets['digits']:
            pool_size += 10
        if char_sets['special']:
            pool_size += 33  # Common special characters
        
        # Calculate entropy
        entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
        return entropy
    
    def check_password_strength(self, password: str) -> Dict:
        """Check password strength based on various criteria"""
        strength = {
            'length': len(password),
            'has_lower': any(c.islower() for c in password),
            'has_upper': any(c.isupper() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'is_common': password.lower() in self.common_passwords,
            'entropy': self.calculate_entropy(password)
        }
        
        # Overall strength rating
        score = 0
        if strength['length'] >= 8: score += 1
        if strength['length'] >= 12: score += 1
        if strength['has_lower']: score += 1
        if strength['has_upper']: score += 1
        if strength['has_digit']: score += 1
        if strength['has_special']: score += 2
        if not strength['is_common']: score += 2
        
        if score <= 3:
            strength['rating'] = "Very Weak"
        elif score <= 5:
            strength['rating'] = "Weak"
        elif score <= 7:
            strength['rating'] = "Moderate"
        elif score <= 9:
            strength['rating'] = "Strong"
        else:
            strength['rating'] = "Very Strong"
            
        return strength
    
    def check_hibp_password(self, password: str) -> Tuple[bool, int]:
        """Check if password has been breached using HaveIBeenPwned API"""
        # Create SHA-1 hash of password
        sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_password[:5], sha1_password[5:]
        
        try:
            # Make request to HIBP API
            self.animate_loading("Checking against breach database")
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            # Check if our password hash suffix is in the response
            hashes = [line.split(':') for line in response.text.splitlines()]
            for h, count in hashes:
                if h == suffix:
                    return True, int(count)
                    
            return False, 0
            
        except requests.RequestException:
            return False, -1  # -1 indicates API error
    
    def check_hibp_email(self, email: str) -> Tuple[bool, List[str]]:
        """Check if email has been breached using HaveIBeenPwned API"""
        try:
            self.animate_loading("Checking email against breach database")
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                'User-Agent': 'PasswordStrengthChecker/1.0',
                'hibp-api-key': 'your-api-key-here'  # You need to get an API key from HIBP
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 404:
                return False, []
            elif response.status_code == 200:
                breaches = [breach['Name'] for breach in response.json()]
                return True, breaches
            else:
                return False, []
                
        except requests.RequestException:
            return False, []
    
    def display_results(self, password: str, email: str = ""):
        """Display password analysis results in a structured format"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        print("🔐 PASSWORD STRENGTH ANALYSIS {🕷️@SPYDOBYTE}")
        print("=" * 50)
        
        # Password strength analysis
        strength = self.check_password_strength(password)
        
        print("\n📊 Password Metrics:")
        print("├── Length: {}".format(strength['length']))
        print("├── Contains lowercase: {}".format("✓" if strength['has_lower'] else "✗"))
        print("├── Contains uppercase: {}".format("✓" if strength['has_upper'] else "✗"))
        print("├── Contains digits: {}".format("✓" if strength['has_digit'] else "✗"))
        print("├── Contains special chars: {}".format("✓" if strength['has_special'] else "✗"))
        print("├── Common password: {}".format("✓" if strength['is_common'] else "✗"))
        print("└── Entropy: {:.2f} bits".format(strength['entropy']))
        
        print(f"\n🏆 Strength Rating: {strength['rating']}")
        
        # HIBP Password check
        print("\n🔍 Breach Check Results:")
        breached, count = self.check_hibp_password(password)
        
        if breached:
            print(f"├── Password breached: ✓ (found in {count} breaches)")
        elif count == -1:
            print("├── Password breached: ? (API error)")
        else:
            print("├── Password breached: ✗ (not found in known breaches)")
        
        # HIBP Email check if provided
        if email:
            breached, breaches = self.check_hibp_email(email)
            if breached:
                print(f"└── Email breached: ✓ (found in {len(breaches)} breaches: {', '.join(breaches)})")
            else:
                print("└── Email breached: ✗ (not found in known breaches)")
        else:
            print("└── Email breached: - (no email provided)")
        
        print("\n" + "=" * 50)
        
        # Recommendations
        print("\n💡 Recommendations:")
        if strength['length'] < 8:
            print("├── Use at least 8 characters")
        if not strength['has_lower']:
            print("├── Add lowercase letters")
        if not strength['has_upper']:
            print("├── Add uppercase letters")
        if not strength['has_digit']:
            print("├── Add numbers")
        if not strength['has_special']:
            print("├── Add special characters")
        if strength['is_common']:
            print("├── Avoid common passwords")
        if breached:
            print("└── CHANGE THIS PASSWORD IMMEDIATELY")
        print()

def main():
    checker = PasswordStrengthChecker()
    
    # Intro animation
    checker.decode_animation("Initializing Password Strength Analyzer...🕷️@SpydoByte")
    time.sleep(1)
    
    # Get user input
    print("\n" + "=" * 50)
    password = input("Enter password to analyze: ")
    email = input("Enter email to check (optional): ")
    
    # Display analysis with loading animation
    checker.decode_animation("Analyzing password strength...")
    checker.display_results(password, email)

if __name__ == "__main__":
    main()
