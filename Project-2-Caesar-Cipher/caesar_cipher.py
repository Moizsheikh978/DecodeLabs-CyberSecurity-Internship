def encrypt_text(text, shift):
    encrypted = ""

    for char in text:
        # Encrypt uppercase letters
        if char.isupper():
            encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

        # Encrypt lowercase letters
        elif char.islower():
            encrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

        # Keep spaces, numbers, and symbols unchanged
        else:
            encrypted += char

    return encrypted


def decrypt_text(text, shift):
    decrypted = ""

    for char in text:
        # Decrypt uppercase letters
        if char.isupper():
            decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))

        # Decrypt lowercase letters
        elif char.islower():
            decrypted += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

        # Keep spaces, numbers, and symbols unchanged
        else:
            decrypted += char

    return decrypted


print("====================================")
print(" Basic Encryption & Decryption Tool ")
print(" Caesar Cipher Method")
print("====================================")

user_text = input("Enter the text you want to encrypt: ")
shift_key = int(input("Enter shift key number: "))

encrypted_output = encrypt_text(user_text, shift_key)
decrypted_output = decrypt_text(encrypted_output, shift_key)

print("\n---------- RESULT ----------")
print("Original Text  :", user_text)
print("Encrypted Text :", encrypted_output)
print("Decrypted Text :", decrypted_output)

if user_text == decrypted_output:
    print("\nVerification: Decryption successful. Original text recovered.")
else:
    print("\nVerification: Decryption failed.")
