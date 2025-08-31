def caesar_cipher(text, shift, mode):
    result = ""
    
    for char in text:
        if char.isalpha(): 
            shift_amount = shift % 26  
            if mode == "decrypt":
                shift_amount = -shift_amount
            if char.isupper():
                new_char = chr((ord(char) - 65 + shift_amount) % 26 + 65)
            else:
                new_char = chr((ord(char) - 97 + shift_amount) % 26 + 97)
            result += new_char
        else:
            result += char
    return result

if __name__ == "__main__":
    print("=== Caesar Cipher Program ===")
    message = input("Enter your message: ")
    shift = int(input("Enter shift value (e.g. 3): "))
    
    encrypted = caesar_cipher(message, shift, "encrypt")
    print("\nEncrypted Message:", encrypted)
    
    decrypted = caesar_cipher(encrypted, shift, "decrypt")
    print("Decrypted Message:", decrypted)