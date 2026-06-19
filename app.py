import streamlit as st
import re
import hashlib
import random
import string
import secrets
import math
from datetime import datetime

# Page configuration
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔐",
    layout="centered"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .stTitle { color: #2c3e50; }
    .strong { color: #27ae60; font-weight: bold; }
    .weak { color: #e74c3c; font-weight: bold; }
    .fair { color: #f39c12; font-weight: bold; }
    .password-box {
        background-color: #f0f2f6;
        padding: 10px;
        border-radius: 5px;
        font-family: monospace;
        font-size: 18px;
        text-align: center;
        margin: 10px 0;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'password_history' not in st.session_state:
    st.session_state.password_history = []

# Common passwords list
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "bailey", "shadow", "123123", "654321", "superman",
    "qazwsx", "michael", "football", "password1", "admin",
    "welcome", "password123", "p@ssword", "p@ssw0rd"
}

def calculate_entropy(password):
    """Calculate password entropy."""
    charset_size = 0
    if re.search(r'[a-z]', password): charset_size += 26
    if re.search(r'[A-Z]', password): charset_size += 26
    if re.search(r'\d', password): charset_size += 10
    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 32
    return len(password) * math.log2(charset_size) if charset_size > 0 else 0

def estimate_crack_time(entropy):
    """Estimate time to crack password."""
    guesses_per_second = 1e11  # 100 billion guesses per second
    combinations = 2 ** entropy
    seconds = combinations / guesses_per_second
    
    if seconds < 1:
        return "Instantly ⚡"
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

def get_strength_color(score):
    """Get color based on strength score."""
    if score < 40: return "weak"
    elif score < 70: return "fair"
    else: return "strong"

def analyze_password(password):
    """Comprehensive password analysis."""
    analysis = {
        "length": len(password),
        "score": 0,
        "strength": "Very Weak",
        "issues": [],
        "suggestions": [],
        "time_to_crack": "",
        "entropy": 0
    }
    
    # Length check
    if len(password) < 8:
        analysis["issues"].append("❌ Too short (minimum 8 characters)")
    elif len(password) < 12:
        analysis["issues"].append("⚠️ Moderate length (recommend 12+ characters)")
        analysis["score"] += 10
    else:
        analysis["score"] += 25
    
    # Complexity checks
    checks = {
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digits": bool(re.search(r'\d', password)),
        "special": bool(re.search(r'[!@#$%^&*(),.?\":{}|<>]', password))
    }
    
    for check in checks.values():
        if check: analysis["score"] += 15
    
    # Pattern checks
    if re.search(r'(.)\1{2,}', password):
        analysis["issues"].append("⚠️ Contains repeated characters")
        analysis["score"] -= 10
    
    if re.search(r'(123|abc|qwe|asd|zxc)', password.lower()):
        analysis["issues"].append("⚠️ Contains sequential characters")
        analysis["score"] -= 10
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        analysis["issues"].append("❌ This is a commonly used password!")
        analysis["score"] -= 25
    
    # History check
    if password in st.session_state.password_history:
        analysis["issues"].append("⚠️ Password has been used before")
        analysis["score"] -= 15
    
    # Calculate entropy
    analysis["entropy"] = calculate_entropy(password)
    analysis["time_to_crack"] = estimate_crack_time(analysis["entropy"])
    
    # Normalize score
    analysis["score"] = max(0, min(100, analysis["score"]))
    
    # Determine strength
    if analysis["score"] < 20:
        analysis["strength"] = "Very Weak"
    elif analysis["score"] < 40:
        analysis["strength"] = "Weak"
    elif analysis["score"] < 60:
        analysis["strength"] = "Fair"
    elif analysis["score"] < 80:
        analysis["strength"] = "Strong"
    else:
        analysis["strength"] = "Very Strong"
    
    # Generate suggestions
    if len(password) < 12:
        analysis["suggestions"].append("📏 Use at least 12 characters")
    if not checks["uppercase"]:
        analysis["suggestions"].append("🔠 Add uppercase letters")
    if not checks["lowercase"]:
        analysis["suggestions"].append("🔡 Add lowercase letters")
    if not checks["digits"]:
        analysis["suggestions"].append("🔢 Add numbers")
    if not checks["special"]:
        analysis["suggestions"].append("✨ Add special characters (!@#$%)")
    
    return analysis

def generate_strong_password(length=16):
    """Generate a strong random password."""
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    password = [
        secrets.choice(uppercase),
        secrets.choice(lowercase),
        secrets.choice(digits),
        secrets.choice(special)
    ]
    
    all_chars = uppercase + lowercase + digits + special
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))
    random.shuffle(password)
    
    return ''.join(password)

def generate_passphrase(word_count=4):
    """Generate a memorable passphrase."""
    words = ["correct", "horse", "battery", "staple", "ocean", "mountain",
             "river", "forest", "desert", "valley", "thunder", "lightning",
             "silver", "golden", "crystal", "diamond", "eagle", "falcon",
             "dolphin", "whale", "tiger", "panther", "phoenix", "dragon"]
    
    chosen = [secrets.choice(words) for _ in range(word_count)]
    separator = secrets.choice(["!", "@", "#", "$", "%", "&", "*"])
    number = str(secrets.randbelow(100))
    
    return separator.join(chosen) + number

# Main App
st.title("🔐 Password Strength Analyzer")
st.markdown("---")

# Sidebar
with st.sidebar:
    st.header("📊 About")
    st.info(
        "This tool evaluates password strength based on:\n"
        "- Length & Complexity\n"
        "- Character Variety\n"
        "- Common Patterns\n"
        "- Entropy Analysis\n"
        "- Password History"
    )
    
    st.header("🛠️ Tools")
    tab1, tab2, tab3 = st.tabs(["📝 Analyze", "🎲 Generate", "📜 History"])
    
    with tab2:
        st.subheader("Generate Password")
        pass_length = st.slider("Password Length", 12, 32, 16)
        if st.button("🎲 Generate Strong Password", use_container_width=True):
            new_pass = generate_strong_password(pass_length)
            st.session_state.generated_password = new_pass
            st.code(new_pass, language="text")
            
            # Copy button
            st.button("📋 Copy to Clipboard", 
                     on_click=lambda: st.write(f'<script>navigator.clipboard.writeText("{new_pass}")</script>', 
                     unsafe_allow_html=True))
        
        st.markdown("---")
        st.subheader("Generate Passphrase")
        word_count = st.slider("Number of Words", 3, 6, 4, key="words")
        if st.button("🎯 Generate Passphrase", use_container_width=True):
            passphrase = generate_passphrase(word_count)
            st.code(passphrase, language="text")
    
    with tab3:
        st.subheader("Password History")
        if st.session_state.password_history:
            for i, pwd in enumerate(st.session_state.password_history[-5:], 1):
                st.text(f"{i}. {'*' * len(pwd)}")
        else:
            st.info("No password history yet")
        
        if st.button("🗑️ Clear History", use_container_width=True):
            st.session_state.password_history = []
            st.rerun()

# Main content - Password input
col1, col2 = st.columns([3, 1])
with col1:
    password = st.text_input("Enter a password to analyze:", 
                            type="password",
                            placeholder="Type or paste your password here...")

with col2:
    show_password = st.checkbox("👁️ Show")
    if show_password and password:
        st.info(password)

# Analyze button
if st.button("🔍 Analyze Password", type="primary", use_container_width=True):
    if password:
        analysis = analyze_password(password)
        
        # Add to history
        if password not in st.session_state.password_history:
            st.session_state.password_history.append(password)
        
        # Display results
        st.markdown("---")
        st.header("📊 Analysis Results")
        
        # Score and strength meter
        col1, col2 = st.columns([1, 2])
        with col1:
            strength_class = get_strength_color(analysis['score'])
            st.markdown(f"<h2 class='{strength_class}'>{analysis['strength']}</h2>", 
                       unsafe_allow_html=True)
            st.metric("Score", f"{analysis['score']}/100")
        
        with col2:
            # Progress bar
            st.progress(analysis['score'] / 100)
            st.caption(f"Entropy: {analysis['entropy']:.2f} bits")
            st.caption(f"Estimated crack time: {analysis['time_to_crack']}")
        
        # Issues and Suggestions
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("⚠️ Issues")
            if analysis['issues']:
                for issue in analysis['issues']:
                    st.write(issue)
            else:
                st.success("✅ No issues found!")
        
        with col2:
            st.subheader("💡 Suggestions")
            if analysis['suggestions']:
                for suggestion in analysis['suggestions']:
                    st.write(suggestion)
            else:
                st.success("✅ Password is strong!")
        
        # Password characteristics
        st.markdown("---")
        st.subheader("🔍 Password Characteristics")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Length", f"{analysis['length']} chars",
                     delta="Good" if analysis['length'] >= 12 else "Short")
        with col2:
            has_upper = bool(re.search(r'[A-Z]', password))
            st.metric("Uppercase", "✅" if has_upper else "❌")
        with col3:
            has_lower = bool(re.search(r'[a-z]', password))
            st.metric("Lowercase", "✅" if has_lower else "❌")
        with col4:
            has_digit = bool(re.search(r'\d', password))
            st.metric("Numbers", "✅" if has_digit else "❌")
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
            st.metric("Special Chars", "✅" if has_special else "❌")
        with col2:
            has_repeated = bool(re.search(r'(.)\1{2,}', password))
            st.metric("Repeated", "⚠️" if has_repeated else "✅")
        with col3:
            has_sequential = bool(re.search(r'(123|abc|qwe)', password.lower()))
            st.metric("Sequential", "⚠️" if has_sequential else "✅")
        with col4:
            is_common = password.lower() in COMMON_PASSWORDS
            st.metric("Common", "⚠️" if is_common else "✅")
    else:
        st.warning("Please enter a password to analyze")

# Footer
st.markdown("---")
st.markdown(
    "<p style='text-align: center; color: gray;'>"
    "🔐 Password Strength Analyzer | Cybersecurity Project | Built with Streamlit"
    "</p>",
    unsafe_allow_html=True
)