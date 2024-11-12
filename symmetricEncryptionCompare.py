import time
import tracemalloc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Helper function to encrypt and decrypt, with memory measurement
def encrypt_decrypt(data, algorithm, key, iv):
    tracemalloc.start()  # Start memory tracking
    
    cipher = Cipher(algorithm, modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Encrypt
    start = time.time()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    encrypt_time = time.time() - start

    # Memory usage after encryption
    _, peak_memory_encrypt = tracemalloc.get_traced_memory()

    # Decrypt
    start = time.time()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    decrypt_time = time.time() - start

    # Memory usage after decryption
    _, peak_memory_decrypt = tracemalloc.get_traced_memory()
    tracemalloc.stop()  # Stop memory tracking

    return encrypt_time, decrypt_time, peak_memory_encrypt, peak_memory_decrypt

# Function to compare performance and memory of different algorithms
def compare_symmetric_algorithms(data):
    # AES
    aes_key = os.urandom(32)  # AES-256 key size
    aes_iv = os.urandom(16)   # AES block size
    aes_encrypt_time, aes_decrypt_time, aes_mem_encrypt, aes_mem_decrypt = encrypt_decrypt(
        data, algorithms.AES(aes_key), aes_key, aes_iv
    )

    # Triple DES
    triple_des_key = os.urandom(24)  # Triple DES key size
    triple_des_iv = os.urandom(8)    # Triple DES block size
    triple_des_encrypt_time, triple_des_decrypt_time, triple_des_mem_encrypt, triple_des_mem_decrypt = encrypt_decrypt(
        data, algorithms.TripleDES(triple_des_key), triple_des_key, triple_des_iv
    )

    # ChaCha20
    chacha_key = os.urandom(32)  # ChaCha20 key size
    chacha_nonce = os.urandom(16) # ChaCha20 nonce size
    cipher = Cipher(algorithms.ChaCha20(chacha_key, chacha_nonce), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()

    # Measure ChaCha20 encryption time and memory usage
    tracemalloc.start()
    start = time.time()
    ciphertext = encryptor.update(data)
    chacha_encrypt_time = time.time() - start
    _, chacha_mem_encrypt = tracemalloc.get_traced_memory()

    # Measure ChaCha20 decryption time and memory usage
    start = time.time()
    plaintext = decryptor.update(ciphertext)
    chacha_decrypt_time = time.time() - start
    _, chacha_mem_decrypt = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Print results
    print(f"AES Encrypt Time: {aes_encrypt_time:.6f} seconds, Memory: {aes_mem_encrypt / 1024:.2f} KB")
    print(f"AES Decrypt Time: {aes_decrypt_time:.6f} seconds, Memory: {aes_mem_decrypt / 1024:.2f} KB")
    print(f"Triple DES Encrypt Time: {triple_des_encrypt_time:.6f} seconds, Memory: {triple_des_mem_encrypt / 1024:.2f} KB")
    print(f"Triple DES Decrypt Time: {triple_des_decrypt_time:.6f} seconds, Memory: {triple_des_mem_decrypt / 1024:.2f} KB")
    print(f"ChaCha20 Encrypt Time: {chacha_encrypt_time:.6f} seconds, Memory: {chacha_mem_encrypt / 1024:.2f} KB")
    print(f"ChaCha20 Decrypt Time: {chacha_decrypt_time:.6f} seconds, Memory: {chacha_mem_decrypt / 1024:.2f} KB")

if __name__ == "__main__":
    # Example data to encrypt and decrypt
    data = b"This is a test message for encryption performance comparison."

    compare_symmetric_algorithms(data)
