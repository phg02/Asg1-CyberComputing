import time
import tracemalloc
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

# Sample message for encryption
message = b"Testing RSA and ECC asymmetric encryption."

# RSA Encryption and Decryption Performance
def rsa_encryption_performance():
    tracemalloc.start()
    start_time = time.time()

    # RSA key generation
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_key = rsa_private_key.public_key()

    # Encrypt message with RSA public key
    rsa_ciphertext = rsa_public_key.encrypt(
        message,
        padding.PKCS1v15()  # Using basic RSA padding without hashing
    )

    # Decrypt message with RSA private key
    rsa_plaintext = rsa_private_key.decrypt(
        rsa_ciphertext,
        padding.PKCS1v15()
    )

    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate time and memory usage
    time_taken = end_time - start_time
    memory_used = peak - current

    return time_taken, memory_used

# ECC Key Exchange (ECDH) Performance
def ecc_key_exchange_performance():
    tracemalloc.start()
    start_time = time.time()

    # ECC key generation for two parties
    ecc_private_key_1 = ec.generate_private_key(ec.SECP256R1())
    ecc_private_key_2 = ec.generate_private_key(ec.SECP256R1())
    ecc_public_key_1 = ecc_private_key_1.public_key()
    ecc_public_key_2 = ecc_private_key_2.public_key()

    # Perform ECDH key exchange to derive shared keys (no hashing or additional processing)
    shared_key_1 = ecc_private_key_1.exchange(ec.ECDH(), ecc_public_key_2)
    shared_key_2 = ecc_private_key_2.exchange(ec.ECDH(), ecc_public_key_1)

    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Calculate time and memory usage
    time_taken = end_time - start_time
    memory_used = peak - current

    return time_taken, memory_used

# Run RSA and ECC performance tests
rsa_time, rsa_memory = rsa_encryption_performance()
ecc_time, ecc_memory = ecc_key_exchange_performance()

print("RSA Performance:")
print(f"Time taken: {rsa_time:.6f} seconds")
print(f"Memory usage: {rsa_memory / 1024:.2f} KB\n")

print("ECC Performance (ECDH Key Exchange):")
print(f"Time taken: {ecc_time:.6f} seconds")
print(f"Memory usage: {ecc_memory / 1024:.2f} KB")
