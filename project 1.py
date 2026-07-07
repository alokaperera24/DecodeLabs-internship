"""
DecodeLabs Industrial Training Kit - Cyber Security
Project 1: Password Strength Checker

Goal: Evaluate a password and classify it as Weak, Medium, or Strong
based on length and character variety (numbers, symbols, uppercase).

Key Skills demonstrated: string handling, conditional logic, security basics.
"""

import string

# A small sample of commonly leaked / breached passwords.
# (Bonus feature suggested in the training brief: flag known-weak passwords
# instantly, regardless of how "complex" they look.)
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "abc123",
    "password1", "111111", "12345678", "letmein", "iloveyou",
    "admin", "welcome", "monkey", "dragon", "football",
}


def check_length(password: str) -> int:
    """
    Score password length.
    < 8 chars  -> 0 points (immediate weakness per project spec)
    8-11 chars -> 1 point
    12-15 chars-> 2 points
    16+ chars  -> 3 points
    """
    length = len(password)
    if length < 8:
        return 0
    elif length <= 11:
        return 1
    elif length <= 15:
        return 2
    else:
        return 3


def check_character_variety(password: str) -> dict:
    """
    Check which character classes are present in the password.
    Uses Python's built-in any() for a clean, efficient single pass
    (short-circuits as soon as a match is found) instead of a manual loop.
    """
    return {
        "lowercase": any(char.islower() for char in password),
        "uppercase": any(char.isupper() for char in password),
        "digit": any(char.isdigit() for char in password),
        "symbol": any(char in string.punctuation for char in password),
    }


def is_common_password(password: str) -> bool:
    """Check the password against a list of known/leaked weak passwords."""
    return password.lower() in COMMON_PASSWORDS


def calculate_strength(password: str):
    """
    Combine length + character variety into a strength score,
    then classify the password and generate human-readable feedback.

    Returns: (label, score, feedback_list)
    """
    feedback = []

    # Immediate fail conditions
    if not password:
        return "Weak", 0, ["Password cannot be empty."]

    if is_common_password(password):
        return "Weak", 0, ["This password appears in common breach lists. Avoid it entirely."]

    length_score = check_length(password)
    variety = check_character_variety(password)
    variety_score = sum(variety.values())  # 0 to 4

    total_score = length_score + variety_score  # max possible = 3 + 4 = 7

    # Build feedback for whatever is missing
    if length_score == 0:
        feedback.append("Too short: use at least 8 characters.")
    elif length_score < 3:
        feedback.append("Consider making it longer (16+ characters) for better security.")

    if not variety["uppercase"]:
        feedback.append("Add at least one uppercase letter (A-Z).")
    if not variety["lowercase"]:
        feedback.append("Add at least one lowercase letter (a-z).")
    if not variety["digit"]:
        feedback.append("Add at least one number (0-9).")
    if not variety["symbol"]:
        feedback.append("Add at least one symbol (e.g. ! @ # $ %).")

    # Classification thresholds
    if length_score == 0 or total_score <= 3:
        label = "Weak"
    elif total_score <= 5:
        label = "Medium"
    else:
        label = "Strong"

    if not feedback:
        feedback.append("Great job! This password meets all checked criteria.")

    return label, total_score, feedback


def display_result(password: str):
    """Print a formatted strength report for a single password."""
    label, score, feedback = calculate_strength(password)

    print("\n" + "-" * 40)
    print(f"Password Strength: {label}  (score: {score}/7)")
    print("-" * 40)
    for tip in feedback:
        print(f"  - {tip}")
    print("-" * 40)


def main():
    print("=" * 40)
    print(" DecodeLabs Password Strength Checker")
    print("=" * 40)
    print("Type a password to check it, or 'quit' to exit.\n")

    while True:
        password = input("Enter password: ").strip()
        if password.lower() == "quit":
            print("Goodbye, stay secure!")
            break
        display_result(password)


if __name__ == "__main__":
    main()
