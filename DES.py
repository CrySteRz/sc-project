import base64

# initial permutation
PI = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# first key permutation
CP_1 = [57, 49, 41, 33, 25, 17, 9,
        1, 58, 50, 42, 34, 26, 18,
        10, 2, 59, 51, 43, 35, 27,
        19, 11, 3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14, 6, 61, 53, 45, 37, 29,
        21, 13, 5, 28, 20, 12, 4]

# second key permutation
CP_2 = [14, 17, 11, 24, 1, 5, 3, 28,
        15, 6, 21, 10, 23, 19, 12, 4,
        26, 8, 16, 7, 27, 20, 13, 2,
        41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56,
        34, 53, 46, 42, 50, 36, 29, 32]

# expansion step
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# substitution boxes
S_BOX = [      
[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
 [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
 [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
 [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
],

[[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
 [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
 [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
 [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
],

[[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
 [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
 [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
 [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
],

[[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
 [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
 [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
 [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
],  

[[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
 [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
 [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
 [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
], 

[[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
 [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
 [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
 [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
], 

[[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
 [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
 [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
 [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
],
   
[[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
 [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
 [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
 [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]
]

# permutation step
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# final permutation
PI_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

# number of bits to shift the key for each round
SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

# function to perform the initial permutation
def initial_permutation(data):
    permuted_data = [data[i - 1] for i in PI]
    return permuted_data

# function to generate the round keys
def generate_round_keys(master_key):
    round_keys = []
    key = [master_key[i - 1] for i in CP_1]
    for shift in SHIFT:
        left_half = key[:28]
        right_half = key[28:]
        left_half = left_half[shift:] + left_half[:shift]
        right_half = right_half[shift:] + right_half[:shift]
        key = left_half + right_half
        round_key = [key[i - 1] for i in CP_2]
        round_keys.append(round_key)
    return round_keys

# function to perform the expansion step
def expansion_permutation(data):
    expanded_data = [data[i - 1] for i in E]
    return expanded_data

# function to perform the substitution step
def substitute(data):
    substituted_data = []
    for i in range(0, 48, 6):
        row = int(''.join([str(data[i]), str(data[i + 5])]), 2)
        col = int(''.join([str(data[i + 1]), str(data[i + 2]), str(data[i + 3]), str(data[i + 4])]), 2)
        val = S_BOX[i // 6][row][col]
        substituted_data.extend([int(x) for x in bin(val)[2:].zfill(4)])
    return substituted_data

# function to perform the permutation step
def permutation(data):
    permuted_data = [data[i - 1] for i in P]
    return permuted_data

# function to perform the final permutation
def final_permutation(data):
    permuted_data = [data[i - 1] for i in PI_1]
    return permuted_data

# function to encrypt a message using the DES algorithm
def des_encrypt(data, key):
    round_keys = generate_round_keys(key)
    data = initial_permutation(data)
    left_half = data[:32]
    right_half = data[32:]
    for round_key in round_keys:
        expanded_data = expansion_permutation(right_half)
        xor_result = [left ^ right for left, right in zip(expanded_data, round_key)]
        substituted_data = substitute(xor_result)
        permuted_data = permutation(substituted_data)
        new_right_half = [left ^ right for left, right in zip(permuted_data, left_half)]
        left_half = right_half
        right_half = new_right_half
    encrypted_data = final_permutation(right_half + left_half)
    return encrypted_data

# function to decrypt a message using the DES algorithm
def des_decrypt(data, key):
    round_keys = generate_round_keys(key)
    data = initial_permutation(data)
    left_half = data[:32]
    right_half = data[32:]
    for round_key in reversed(round_keys):
        expanded_data = expansion_permutation(right_half)
        xor_result = [left ^ right for left, right in zip(expanded_data, round_key)]
        substituted_data = substitute(xor_result)
        permuted_data = permutation(substituted_data)
        new_right_half = [left ^ right for left, right in zip(permuted_data, left_half)]
        left_half = right_half
        right_half = new_right_half

    decrypted_data = final_permutation(right_half + left_half)
    return decrypted_data

# function to convert a string to a list of bits
def string_to_bits(s):
    return [int(bit) for char in s.encode('utf-8') for bit in '{:08b}'.format(char)]

# function to convert a list of bits to a string
def bits_to_string(bits):
    bytes_list = [int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)]
    return bytes(bytes_list).decode('utf-8', errors='ignore')

# function to pad the data to a multiple of the block size
def pkcs7_pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

# function to convert a list of bits to a base64 string
def bits_to_base64(bits):
    bytes_array = bytes([int(''.join(map(str, bits[i:i+8])), 2) for i in range(0, len(bits), 8)])
    return base64.b64encode(bytes_array).decode('utf-8')

# function to convert a base64 string to a list of bits
def base64_to_bits(base64_string):
    bytes_array = base64.b64decode(base64_string)
    return [int(bit) for byte in bytes_array for bit in '{:08b}'.format(byte)]

# function to encrypt a message using the DES algorithm
def encrypt_string(plaintext, key_text):
    key = string_to_bits(key_text)
    block_size = 64
    plaintext_padded = pkcs7_pad(plaintext.encode('utf-8'), block_size // 8)
    plaintext_blocks = [plaintext_padded[i:i+block_size//8] for i in range(0, len(plaintext_padded), block_size//8)]
    encrypted_blocks = []
    for block in plaintext_blocks:
        block_bits = [int(bit) for byte in block for bit in '{:08b}'.format(byte)]
        encrypted_block = des_encrypt(block_bits, key)
        encrypted_blocks.append(encrypted_block)
    encrypted_bits_flat = [bit for block in encrypted_blocks for bit in block]
    return bits_to_base64(encrypted_bits_flat)

# function to decrypt a message using the DES algorithm
def decrypt_string(encrypted_base64, key_text):
    key = string_to_bits(key_text)
    encrypted_bits = base64_to_bits(encrypted_base64)
    block_size = 64
    num_blocks = len(encrypted_bits) // block_size
    decrypted_blocks = []
    for i in range(num_blocks):
        block_start = i * block_size
        block_end = block_start + block_size
        decrypted_block = des_decrypt(encrypted_bits[block_start:block_end], key)
        decrypted_blocks.append(decrypted_block)
    
    decrypted_bits_flat = [bit for block in decrypted_blocks for bit in block]
    return bits_to_string(decrypted_bits_flat)

# function to validate the encryption/decryption key
def validate_key():
    while True:
        key_text = input("Enter encryption/decryption key (minimum 8 characters): ")
        if len(key_text) >= 8:
            return key_text
        else:
            print("Key must be at least 8 characters long. Please try again.")

# function to start the DES encryption/decryption process
# interact with the user to encrypt or decrypt messages
def start():
    while True:
        choice = input("Do you want to encrypt or decrypt data? (e/d) or quit (q): ").lower()
        if choice == 'e':
            plaintext = input("Enter data to encrypt (text): ")
            key_text = validate_key()
            encrypted = encrypt_string(plaintext, key_text)
            print("Encrypted data (Base64):", encrypted)
        elif choice == 'd':
            encrypted_base64 = input("Enter data to decrypt (Base64 string): ")
            key_text = validate_key()
            decrypted = decrypt_string(encrypted_base64, key_text)
            print("Decrypted data: ", decrypted)
        elif choice == 'q':
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please choose 'e' to encrypt, 'd' to decrypt, or 'q' to quit.")