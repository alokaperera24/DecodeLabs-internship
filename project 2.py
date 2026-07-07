# ==========================================
# DecodeLabs Cyber Security Project 2
# Basic Encryption & Decryption (Caesar Cipher)
# ==========================================

def encrypt(text, shift):
    encrypted = ""

    for char in text:
        if char.isupper():
            encrypted += chr((ord(char) - ord('A') + shift) % 26 + ord('A'))

        elif char.islower():
            encrypted += chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

        else:
            encrypted += char

    return encrypted


def decrypt(text, shift):
    decrypted = ""

    for char in text:
        if char.isupper():
            decrypted += chr((ord(char) - ord('A') - shift) % 26 + ord('A'))

        elif char.islower():
            decrypted += chr((ord(char) - ord('a') - shift) % 26 + ord('a'))

        else:
            decrypted += char

    return decrypted


print("=" * 50)
print("      BASIC ENCRYPTION & DECRYPTION")
print("           Caesar Cipher")
print("=" * 50)

message = input("Enter your message: ")

while True:
    try:
        shift = int(input("Enter Shift Key (1-25): "))
        if 1 <= shift <= 25:
            break
        else:
            print("Shift key must be between 1 and 25.")
    except ValueError:
        print("Please enter a valid number.")

encrypted_message = encrypt(message, shift)
decrypted_message = decrypt(encrypted_message, shift)

print("\n========== RESULTS ==========")
print("Original Message :", message)
print("Encrypted Message:", encrypted_message)
print("Decrypted Message:", decrypted_message)
print("=============================")