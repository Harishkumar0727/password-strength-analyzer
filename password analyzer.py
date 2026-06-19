import re
import hashlib
import random
import string
import sqlite3
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import secrets

class PasswordStrengthAnalyzer:
    def __init__(self, db_path: str = "password_history.db"):
        """Initialize the Password Strength Analyzer."""
        self.db_path = db_path
        self.common_passwords = self._load_common_passwords()
        self.init_database()
    
    def _load_common_passwords(self) -> set:
        """Load common weak passwords."""
        common = {
            "password", "123456", "12345678", "qwerty", "abc123",
            "monkey", "1234567", "letmein", "trustno1", "dragon",
            "baseball", "iloveyou", "master", "sunshine", "ashley",
            "bailey", "shadow", "123123", "654321", "superman",
            "qazwsx", "michael", "football", "password1", "admin",
            "welcome", "password123", "p@ssword", "p@ssw0rd"
        }
        return common
    
    def init_database(self):
        """Initialize database for password history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def _hash_password(self, password: str) -> str:
        """Hash password for secure storage."""
        salt = secrets.token_hex(16)
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
    
    def check_password_reuse(self, password: str) -> Tuple[bool, List[datetime]]:
        """Check if password has been used before."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all historical hashes
        cursor.execute("SELECT password_hash, created_at FROM password_history")
        history = cursor.fetchall()
        conn.close()
        
        reused_times = []
        # Simple check - in production, use proper password hashing like bcrypt
        for stored_hash, created_at in history:
            if hashlib.sha256(password.encode()).hexdigest()[:16] == stored_hash[:16]:
                reused_times.append(datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S"))
        
        return len(reused_times) > 0, reused_times
    
    def save_password(self, password: str) -> bool:
        """Save password hash to history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            password_hash = self._hash_password(password)
            cursor.execute(
                "INSERT INTO password_history (password_hash) VALUES (?)",
                (password_hash,)
            )
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving password: {e}")
            return False
    
    def analyze_password(self, password: str) -> Dict:
        """Comprehensive password analysis."""
        analysis = {
            "password": password,
            "length": len(password),
            "score": 0,
            "max_score": 100,
            "strength": "Very Weak",
            "issues": [],
            "suggestions": [],
            "time_to_crack": "",
            "entropy": 0,
            "is_unique": True
        }
        
        # Check length
        if len(password) < 8:
            analysis["issues"].append("Password is too short (minimum 8 characters)")
            analysis["score"] += 0
        elif len(password) < 12:
            analysis["issues"].append("Password length is moderate (recommend 12+ characters)")
            analysis["score"] += 10
        else:
            analysis["score"] += 20
        
        # Check complexity
        complexity_checks = {
            "uppercase": (bool(re.search(r'[A-Z]', password)), "uppercase letters"),
            "lowercase": (bool(re.search(r'[a-z]', password)), "lowercase letters"),
            "digits": (bool(re.search(r'\d', password)), "numbers"),
            "special": (bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)), "special characters")
        }
        
        missing_types = [desc for check, desc in complexity_checks.values() if not check]
        if missing_types:
            analysis["issues"].append(f"Missing: {', '.join(missing_types)}")
        
        # Add score for each character type present
        for check, _ in complexity_checks.values():
            if check:
                analysis["score"] += 15
        
        # Check for patterns
        if re.search(r'(.)\1{2,}', password):
            analysis["issues"].append("Contains repeated characters")
            analysis["score"] -= 10
        
        if re.search(r'(123|abc|qwe|asd|zxc)', password.lower()):
            analysis["issues"].append("Contains sequential characters")
            analysis["score"] -= 10
        
        # Check for common passwords
        if password.lower() in self.common_passwords:
            analysis["issues"].append("This is a commonly used password")
            analysis["score"] -= 20
        
        # Calculate entropy
        analysis["entropy"] = self._calculate_entropy(password)
        
        # Estimate crack time
        analysis["time_to_crack"] = self._estimate_crack_time(analysis["entropy"])
        
        # Check password history
        is_reused, reused_dates = self.check_password_reuse(password)
        if is_reused:
            analysis["is_unique"] = False
            analysis["issues"].append(f"Password has been used before (last used: {reused_dates[-1]})")
            analysis["score"] -= 15
        
        # Ensure score is within bounds
        analysis["score"] = max(0, min(100, analysis["score"]))
        
        # Determine strength level
        analysis["strength"] = self._get_strength_label(analysis["score"])
        
        # Generate suggestions
        analysis["suggestions"] = self._generate_suggestions(password, analysis)
        
        return analysis
    
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy."""
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            charset_size += 32
        
        if charset_size == 0:
            return 0
        
        import math
        return len(password) * math.log2(charset_size)
    
    def _estimate_crack_time(self, entropy: float) -> str:
        """Estimate time to crack password."""
        # Assuming 100 billion guesses per second (modern GPU cluster)
        guesses_per_second = 1e11
        combinations = 2 ** entropy
        seconds = combinations / guesses_per_second
        
        if seconds < 1:
            return "Instantly"
        elif seconds < 60:
            return f"{seconds:.0f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 315360000:
            return f"{seconds/31536000:.1f} years"
        else:
            return f"{seconds/31536000:.0f} years"
    
    def _get_strength_label(self, score: int) -> str:
        """Convert score to strength label."""
        if score < 20:
            return "Very Weak"
        elif score < 40:
            return "Weak"
        elif score < 60:
            return "Fair"
        elif score < 80:
            return "Strong"
        else:
            return "Very Strong"
    
    def _generate_suggestions(self, password: str, analysis: Dict) -> List[str]:
        """Generate password improvement suggestions."""
        suggestions = []
        
        if len(password) < 12:
            suggestions.append("Use at least 12 characters for better security")
        
        if not re.search(r'[A-Z]', password):
            suggestions.append("Add uppercase letters")
        
        if not re.search(r'[a-z]', password):
            suggestions.append("Add lowercase letters")
        
        if not re.search(r'\d', password):
            suggestions.append("Add numbers")
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            suggestions.append("Add special characters")
        
        if re.search(r'(.)\1{2,}', password):
            suggestions.append("Avoid repeated characters")
        
        if password.lower() in self.common_passwords:
            suggestions.append("Avoid using common words or patterns")
        
        return suggestions
    
    def generate_strong_password(self, length: int = 16) -> str:
        """Generate a strong random password."""
        if length < 12:
            length = 12
        
        uppercase = string.ascii_uppercase
        lowercase = string.ascii_lowercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure at least one of each type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with random characters
        all_chars = uppercase + lowercase + digits + special
        for _ in range(length - 4):
            password.append(secrets.choice(all_chars))
        
        # Shuffle the password
        random.shuffle(password)
        return ''.join(password)
    
    def suggest_alternatives(self, base_password: str, count: int = 5) -> List[Dict]:
        """Generate alternative strong passwords based on user's pattern."""
        alternatives = []
        
        for _ in range(count):
            alternative = self.generate_strong_password()
            analysis = self.analyze_password(alternative)
            alternatives.append({
                "password": alternative,
                "strength": analysis["strength"],
                "score": analysis["score"]
            })
        
        return sorted(alternatives, key=lambda x: x["score"], reverse=True)
    
    def generate_memorable_password(self, word_count: int = 4) -> Dict:
        """Generate a memorable but strong password (passphrase)."""
        word_list = [
            "correct", "horse", "battery", "staple", "ocean", "mountain",
            "river", "forest", "desert", "valley", "thunder", "lightning",
            "silver", "golden", "crystal", "diamond", "eagle", "falcon",
            "dolphin", "whale", "tiger", "panther", "phoenix", "dragon",
            "wizard", "knight", "castle", "bridge", "garden", "island"
        ]
        
        words = [secrets.choice(word_list) for _ in range(word_count)]
        
        # Add numbers and special characters between words
        separator = secrets.choice(["!", "@", "#", "$", "%", "&", "*"])
        number = str(secrets.randbelow(100))
        
        passphrase = separator.join(words) + number
        
        analysis = self.analyze_password(passphrase)
        
        return {
            "password": passphrase,
            "words": words,
            "strength": analysis["strength"],
            "score": analysis["score"],
            "time_to_crack": analysis["time_to_crack"]
        }
    
    def get_password_history(self, limit: int = 10) -> List[Dict]:
        """Retrieve password history."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT password_hash, created_at FROM password_history ORDER BY created_at DESC LIMIT ?",
            (limit,)
        )
        history = cursor.fetchall()
        conn.close()
        
        return [
            {"hash": h[:16] + "...", "created_at": d}
            for h, d in history
        ]


def display_analysis(analyzer: PasswordStrengthAnalyzer, password: str):
    """Display password analysis results in a formatted way."""
    analysis = analyzer.analyze_password(password)
    
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYZER")
    print("="*60)
    
    # Visual strength bar
    bar_length = 40
    filled = int(analysis["score"] / 100 * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)
    
    colors = {
        "Very Weak": "\033[91m",   # Red
        "Weak": "\033[91m",         # Red
        "Fair": "\033[93m",         # Yellow
        "Strong": "\033[92m",       # Green
        "Very Strong": "\033[92m"   # Green
    }
    reset = "\033[0m"
    
    print(f"\nStrength: {colors.get(analysis['strength'], '')}{analysis['strength']}{reset}")
    print(f"Score: {analysis['score']}/100")
    print(f"[{bar}]")
    print(f"Entropy: {analysis['entropy']:.2f} bits")
    print(f"Estimated time to crack: {analysis['time_to_crack']}")
    print(f"Unique password: {'Yes' if analysis['is_unique'] else 'No'}")
    
    if analysis["issues"]:
        print("\n⚠️  Issues found:")
        for issue in analysis["issues"]:
            print(f"  • {issue}")
    
    if analysis["suggestions"]:
        print("\n💡 Suggestions:")
        for suggestion in analysis["suggestions"]:
            print(f"  • {suggestion}")


def main():
    """Main application loop."""
    analyzer = PasswordStrengthAnalyzer()
    
    print("="*60)
    print("      PASSWORD STRENGTH ANALYZER")
    print("="*60)
    print("\nFeatures:")
    print("  • Analyze password strength")
    print("  • Check password complexity")
    print("  • Detect common passwords")
    print("  • Generate strong alternatives")
    print("  • Password history tracking")
    
    while True:
        print("\n" + "="*60)
        print("Options:")
        print("  1. Analyze a password")
        print("  2. Generate strong password")
        print("  3. Generate memorable passphrase")
        print("  4. Get suggestions for alternatives")
        print("  5. View password history")
        print("  6. Exit")
        print("="*60)
        
        choice = input("\nSelect an option (1-6): ").strip()
        
        if choice == "1":
            password = input("\nEnter password to analyze: ")
            display_analysis(analyzer, password)
            
            save = input("\nSave this password to history? (y/n): ").lower()
            if save == 'y':
                analyzer.save_password(password)
                print("✅ Password saved to history!")
        
        elif choice == "2":
            length = input("Enter password length (default 16): ").strip()
            length = int(length) if length.isdigit() else 16
            password = analyzer.generate_strong_password(length)
            print(f"\nGenerated Password: {password}")
            display_analysis(analyzer, password)
        
        elif choice == "3":
            words = input("Number of words (default 4): ").strip()
            words = int(words) if words.isdigit() else 4
            result = analyzer.generate_memorable_password(words)
            print(f"\nMemorable Passphrase: {result['password']}")
            print(f"Words used: {', '.join(result['words'])}")
            print(f"Strength: {result['strength']}")
            print(f"Time to crack: {result['time_to_crack']}")
        
        elif choice == "4":
            base = input("Enter a base word or pattern: ")
            alternatives = analyzer.suggest_alternatives(base, count=3)
            print("\n🔐 Alternative Strong Passwords:")
            for i, alt in enumerate(alternatives, 1):
                print(f"\n{i}. {alt['password']}")
                print(f"   Strength: {alt['strength']} (Score: {alt['score']}/100)")
        
        elif choice == "5":
            history = analyzer.get_password_history(limit=5)
            if history:
                print("\n📜 Password History (last 5):")
                for i, entry in enumerate(history, 1):
                    print(f"  {i}. {entry['hash']} - {entry['created_at']}")
            else:
                print("\nNo password history available.")
        
        elif choice == "6":
            print("\nThank you for using Password Strength Analyzer!")
            break
        
        else:
            print("\n❌ Invalid option. Please try again.")


if __name__ == "__main__":
    main()