# fuzzy_commitment/constants.py

# Security Parameters
N = 512  # Polynomial degree (power of 2)
Q = 12289  # Prime modulus for RLWE
T = 37  # Plaintext modulus (T < Q)
STD_DEV = 3  # Gaussian noise standard deviation

HAMMING_THRESHOLD = 64
# The shared server‐only secret used in hashing
SYSTEM_PARAMETER_S = "d4f7e2a3c1b09f8e6d7c4f2a1b0e9c8d5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"

# A human‐readable server identity string
SERVER_ID = "MedicalServer"

# Hash function
HASH_FUNCTION = "sha3_256"
SERVER_SECRET = b'9lWQLDWiPRY7vo1L_RTvv3ez2J0KTWIfqdsTNjBO8BA='    # e.g. Fernet.generate_key()
SESSION_TIMEOUT = 300