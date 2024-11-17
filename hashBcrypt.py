import bcrypt
import time
import tracemalloc

def hash_string():
    # The string to hash
    string_to_hash = "your-string-to-hash"
    # Define salt rounds
    salt_rounds = 10

    # Start time and memory tracking
    start_time = time.time()
    tracemalloc.start()
    
    # Generate salt with 10 rounds and hash the string
    salt = bcrypt.gensalt(salt_rounds)
    hashed = bcrypt.hashpw(string_to_hash.encode(), salt)
    
    # End time and memory tracking
    end_time = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    # Calculate time taken and memory used
    time_taken = end_time - start_time  # Time in seconds
    memory_used_kb = peak / 1024  # Memory in KB
    
    # Print the results
    print(f"Hashed String: {hashed.decode()}")
    print(f"Time Taken: {time_taken:.3f} seconds")
    print(f"Peak Memory Used: {memory_used_kb:.2f} KB")

# Run the hash function
hash_string()
