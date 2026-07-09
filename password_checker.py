import getpass


def check_password_strength(password):
    # Common weak passwords list
    common_passwords = [
        "password",
        "123456",
        "12345678",
        "qwerty",
        "abc123",
        "admin",
        "letmein",
        "welcome",
        "iloveyou",
        "password123"
    ]

    # Basic checks
    has_uppercase = False
    has_lowercase = False
    has_number = False
    has_symbol = False

    # Single linear scan through the password
    for char in password:
        if char.isupper():
            has_uppercase = True
        elif char.islower():
            has_lowercase = True
        elif char.isdigit():
            has_number = True
        else:
            has_symbol = True

    score = 0
    feedback = []

    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Uppercase check
    if has_uppercase:
        score += 1
    else:
        feedback.append("Add at least one uppercase letter.")

    # Lowercase check
    if has_lowercase:
        score += 1
    else:
        feedback.append("Add at least one lowercase letter.")

    # Number check
    if has_number:
        score += 1
    else:
        feedback.append("Add at least one number.")

    # Symbol check
    if has_symbol:
        score += 1
    else:
        feedback.append("Add at least one symbol, such as @, #, $, %, or !.")

    # Common password check
    if password.lower() in common_passwords:
        score = 0
        feedback.append("This password is too common and easy to guess.")

    # Final strength classification
    if score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Medium"
    else:
        strength = "Strong"

    return strength, feedback


def main():
    print("===================================")
    print("     Password Strength Checker")
    print("===================================")

    password = getpass.getpass("Enter your password: ")

    strength, feedback = check_password_strength(password)

    print("\nPassword Strength:", strength)

    if feedback:
        print("\nSuggestions to improve your password:")
        for item in feedback:
            print("-", item)
    else:
        print("\nGreat! Your password meets the recommended strength requirements.")


if __name__ == "__main__":
    main()