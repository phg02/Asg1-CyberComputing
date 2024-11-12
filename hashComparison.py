import hashlib
import bcrypt
import time
import tracemalloc

def hash_speed_and_memory_test(data, algorithm):
    # Start tracing memory allocations
    tracemalloc.start()
    
    start_time = time.time()
    
    # Perform hashing based on the algorithm
    if algorithm == 'bcrypt':
        hashed = bcrypt.hashpw(data, bcrypt.gensalt())
    else:
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        hashed = hasher.digest()
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    
    # Measure memory consumption
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # Return elapsed time and peak memory usage during hashing
    return elapsed_time, peak

# Data to be hashed
data = b"The quick brown fox jumps over the lazy dog" * 1000  # Repeat to increase data size

# List of algorithms to test
algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'bcrypt']

# Test each algorithm and print the results
for algorithm in algorithms:
    elapsed_time, memory_used = hash_speed_and_memory_test(data, algorithm)
    print(f"{algorithm.upper()} took {elapsed_time:.6f} seconds and used {memory_used / 1024:.2f} KB of memory")
