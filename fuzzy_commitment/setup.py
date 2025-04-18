# fuzzy_commitment/setup.py

import json
from she import RLWE
from fuzzy_commitment.constants import N, Q, T, STD_DEV
from time import perf_counter
SERVER_DATA_FILE = "data/server_data.json"
def setup_phase():
    # Initialize RLWE scheme
    rlwe = RLWE(N, Q, T, STD_DEV)
    # Generate master keypair
    start_time = perf_counter()
    mk, (a0, a1) = rlwe.generate_keys()
    end_time = perf_counter()
    print(f"[Setup Phase] Key Generation Time: {end_time - start_time:.6f} seconds")
    # Public parameter a is the a1 in this implementation
    a = a1
    b = a0  # In the original math, public key is (a, b = a*mk + e mod q)
    public_params = {
        "n": N,
        "q": Q,
        "t": T,
        "a": a.poly.coeffs.tolist(),
        "b": b.poly.coeffs.tolist(),
        "hash_function": "sha3_256"
    }
    secret_params = {
        "mk": mk.poly.coeffs.tolist()
    }
    # Combine and save to server data
    server_data = {
        "public_parameters": public_params,
        "secret_parameters": secret_params
    }
    with open(SERVER_DATA_FILE, "w") as f:
        json.dump(server_data, f, indent=2)

    return public_params  # We can return this to show it on API
