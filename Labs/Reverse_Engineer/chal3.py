def decode_flag():
    # The encoded string from the C code
    encoded = "ZLT{Kdwhafy_ak_fgl_gtxmkuslagf}"
    
    # The key determined in the code (original key + 5 = 18)
    z = 18
    decoded = ""

    for char in encoded:
        if 'a' <= char <= 'z':
            # Decode lowercase
            # We subtract the shift, then handle the wrap-around using modulo 26
            new_char = chr(((ord(char) - ord('a') - z) % 26) + ord('a'))
            decoded += new_char
        elif 'A' <= char <= 'Z':
            # Decode uppercase
            new_char = chr(((ord(char) - ord('A') - z) % 26) + ord('A'))
            decoded += new_char
        else:
            # Leave symbols like { } and _ alone
            decoded += char
            
    return decoded

print(f"Decoded Key: {decode_flag()}")