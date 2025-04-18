# fuzzy_commitment/utils.py

import hashlib
import json
import numpy as np
from fuzzy_commitment.constants import HASH_FUNCTION

def hash_bytes(input_str: str) -> str:
    hasher = hashlib.new(HASH_FUNCTION)
    hasher.update(input_str.encode())
    return hasher.hexdigest()

def xor_hash(h1: str, h2: str) -> str:
    # XOR two hex-encoded hashes
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return bytes(a ^ b for a, b in zip(b1, b2)).hex()

def save_json(filepath, data):
    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)

def load_json(filepath):
    with open(filepath) as f:
        return json.load(f)

def encode_bitstring_to_poly(bits, modulus):
    # pad to length N with zeros
    padded = bits + [0] * (512 - len(bits))
    return np.array(padded) % modulus
