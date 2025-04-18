# fuzzy_commitment/constants.py

# Security Parameters
N = 512  # Polynomial degree (power of 2)
Q = 12289  # Prime modulus for RLWE
T = 37  # Plaintext modulus (T < Q)
STD_DEV = 3  # Gaussian noise standard deviation

HASH_FUNCTION = "sha3_256"  # Hash used for biometric + keys
