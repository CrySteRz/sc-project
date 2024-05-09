import secrets
from sympy import randprime # type: ignore
import os

# function to calculate the greatest common divisor of two numbers
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# function to calculate the extended greatest common divisor of two numbers
def xgcd(a, b):
    x, old_x = 0, 1
    y, old_y = 1, 0
    while b != 0:
        quotient = a // b
        a, b = b, a - quotient * b
        old_x, x = x, old_x - quotient * x
        old_y, y = y, old_y - quotient * y
    return a, old_x, old_y

# function to choose a random number e such that 1 < e < totient and gcd(e, totient) = 1
def choose_e(totient):
    e = secrets.randbelow(totient - 2) + 2
    while gcd(e, totient) != 1:
        e = secrets.randbelow(totient - 2) + 2
    return e

# function to generate RSA public and private keys
def choose_keys():
    prime1 = randprime(10**5, 10**6)
    prime2 = randprime(10**5, 10**6)
    n = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    e = choose_e(totient)
    _, x, _ = xgcd(e, totient)
    d = x % totient if x > 0 else (x + totient) % totient
    return (n, e), (n, d)

# function to write the public and private keys to files
def write_keys(public_key, private_key):
    with open('public_keys.txt', 'w') as f:
        f.write(f'{public_key[0]}\n{public_key[1]}\n')
    with open('private_keys.txt', 'w') as f:
        f.write(f'{private_key[0]}\n{private_key[1]}\n')

# function to read the public and private keys from files
def read_key(file_name):
    if not os.path.exists(file_name):
        raise FileNotFoundError("Key file not found.")
    with open(file_name, 'r') as file:
        n = int(file.readline().strip())
        key = int(file.readline().strip())
    return n, key

# function to encrypt a message using the RSA algorithm
def encrypt(message, n, e, block_size=2):
    padding_length = (block_size - (len(message) % block_size)) % block_size
    if padding_length == 0:
        padding_length = block_size
    padding = os.urandom(padding_length - 1)
    padding = bytes([padding_length]) + padding
    message += padding.decode('latin1')  
    encrypted_blocks = []
    for i in range(0, len(message), block_size):
        block = 0
        for j in range(block_size):
            block += ord(message[i + j]) << (8 * j)
        encrypted_blocks.append(pow(block, e, n))
    return ' '.join(map(str, encrypted_blocks))

# function to decrypt a message using the RSA algorithm
def decrypt(ciphertext, n, d, block_size=2):
    decrypted_message = []
    blocks = map(int, ciphertext.split())
    for block in blocks:
        block = pow(block, d, n)
        block_chars = []
        for j in range(block_size):
            block_chars.append(chr((block >> (8 * j)) & 0xFF))
        decrypted_message.append(''.join(block_chars))
    
    final_block = decrypted_message[-1]
    padding_length = ord(final_block[-1])
    if padding_length <= block_size:
        decrypted_message[-1] = final_block[:-padding_length]
    
    return ''.join(decrypted_message)

# function to start the RSA encryption/decryption process
# interact with the user to generate new keys, encrypt or decrypt messages
def start():
    if input("Generate new RSA keys? (y/n): ").lower() == 'y':
        public_key, private_key = choose_keys()
        write_keys(public_key, private_key)
        print("New keys generated and saved.")

    mode = input("Encrypt or decrypt? (e/d): ").lower()
    if mode == 'e':
        message = input("Enter message to encrypt: ")
        file_name = input("Enter public key file (default 'public_keys.txt'): ") or 'public_keys.txt'
        n, e = read_key(file_name)
        print("Encrypting message...")
        encrypted_message = encrypt(message, n, e)
        print("Encrypted message:", encrypted_message)
    elif mode == 'd':
        ciphertext = input("Enter message to decrypt: ")
        file_name = input("Enter private key file (default 'private_keys.txt'): ") or 'private_keys.txt'
        n, d = read_key(file_name)
        print("Decrypting message...")
        decrypted_message = decrypt(ciphertext, n, d)
        print("Decrypted message:", decrypted_message)
    else:
        print("Invalid option selected.")
