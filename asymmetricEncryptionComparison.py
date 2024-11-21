import time
import tracemalloc
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization

# Sample message for RSA encryption
message = b"Testing RSA and ECC encryption performance."

# RSA Encryption and Decryption Performance
def rsa_performance():
    tracemalloc.start()  # Start memory tracking

    # RSA key generation
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_public_key = rsa_private_key.public_key()

    # Measure encryption time
    start_enc = time.time()
    rsa_ciphertext = rsa_public_key.encrypt(
        message,
        padding.PKCS1v15()  # No hashing in PKCS1v15 padding
    )
    end_enc = time.time()

    # Measure decryption time
    start_dec = time.time()
    rsa_decrypted_message = rsa_private_key.decrypt(
        rsa_ciphertext,
        padding.PKCS1v15()
    )
    end_dec = time.time()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()  # Stop memory tracking

    rsa_encryption_time = end_enc - start_enc
    rsa_decryption_time = end_dec - start_dec
    rsa_memory_usage = peak - current

    return rsa_encryption_time, rsa_decryption_time, rsa_memory_usage

# ECC Key Exchange Performance (ECDH)
def ecc_performance():
    tracemalloc.start()  # Start memory tracking

    # ECC key generation for two parties
    ecc_private_key_1 = ec.generate_private_key(ec.SECP256R1())
    ecc_private_key_2 = ec.generate_private_key(ec.SECP256R1())
    ecc_public_key_1 = ecc_private_key_1.public_key()
    ecc_public_key_2 = ecc_private_key_2.public_key()

    # Measure "encryption" time (simulating key exchange)
    start_enc = time.time()
    shared_key_1 = ecc_private_key_1.exchange(ec.ECDH(), ecc_public_key_2)
    end_enc = time.time()

    # Measure "decryption" time (simulating key exchange from the other side)
    start_dec = time.time()
    shared_key_2 = ecc_private_key_2.exchange(ec.ECDH(), ecc_public_key_1)
    end_dec = time.time()

    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()  # Stop memory tracking

    ecc_encryption_time = end_enc - start_enc
    ecc_decryption_time = end_dec - start_dec
    ecc_memory_usage = peak - current

    return ecc_encryption_time, ecc_decryption_time, ecc_memory_usage

# Run RSA and ECC performance tests
rsa_enc_time, rsa_dec_time, rsa_mem_usage = rsa_performance()
ecc_enc_time, ecc_dec_time, ecc_mem_usage = ecc_performance()

print("RSA Performance without hashing:")
print(f"Encryption time: {rsa_enc_time:.6f} seconds")
print(f"Decryption time: {rsa_dec_time:.6f} seconds")
print(f"Memory usage: {rsa_mem_usage / 1024:.2f} KB\n")

print("ECC (ECDH Key Exchange) Performance without hashing:")
print(f"Encryption time (simulated key exchange): {ecc_enc_time:.6f} seconds")
print(f"Decryption time (simulated key exchange): {ecc_dec_time:.6f} seconds")
print(f"Memory usage: {ecc_mem_usage / 1024:.2f} KB")
