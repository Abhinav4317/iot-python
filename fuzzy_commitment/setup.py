# fuzzy_commitment/setup.py

import json
import numpy as np
from she.Rq import Rq
from fuzzy_commitment.constants import N, Q, T, STD_DEV,SERVER_SECRET
from time import perf_counter
import json
from cryptography.fernet import Fernet
SERVER_DATA_FILE = "data/server_data.json"

def discrete_gaussian_arr(n, q, std):
    # vectorized Gaussian → int64 → mod q
    arr = np.round(std * np.random.randn(n)).astype(np.int64)
    return arr % q

def setup_phase():
    # 1) Warm the Numba/NTT JIT (no timing)
    from she.RLWE import RLWE
    rlwe = RLWE(N, Q, T, STD_DEV)
    rlwe.generate_keys()

    # 2) Real measurement using pure‐NumPy for b = a*mk + e mod (x^n+1, q):
    start = perf_counter()

    # sample mk, a, e as raw arrays
    mk_arr = discrete_gaussian_arr(N, Q, STD_DEV)
    a_arr  = np.random.randint(0, Q, size=N, dtype=np.int64)
    e_arr  = discrete_gaussian_arr(N, Q, STD_DEV)

    # polynomial multiply a_arr⊗mk_arr via fast C-kernel
    # returns length 2N-1 array
    conv = np.polynomial.polynomial.polymul(a_arr, mk_arr).astype(np.int64)

    # reduce mod x^N + 1:  b[i] = (conv[i] - conv[i+N]) mod q
    # note conv[N:] has length N-1, so pad with 0 at the end
    head = conv[:N]  # length N
    tail_raw = conv[N:]  # length N-1
    # pad tail_raw with one zero to get length N
    tail = np.pad(tail_raw, (0, N - tail_raw.shape[0]), constant_values=0)

    b_arr = (head - tail) % Q
    # add error
    b_arr = (b_arr + e_arr) % Q

    # wrap into Rq objects so downstream code sees the same API
    mk = Rq(mk_arr, Q)
    a  = Rq(a_arr,  Q)
    b  = Rq(b_arr,  Q)

    f = Fernet(SERVER_SECRET)
    mk_json = json.dumps(mk.coeffs.tolist()).encode()
    encrypted_mk = f.encrypt(mk_json).decode()
    delta = perf_counter() - start
    print(f"[Setup Phase] KeyGen (NumPy) took {delta*1000:.2f} ms")

    # build JSON‐serializable output
    public_params = {
        "n": N,
        "q": Q,
        "t": T,
        "a": a.coeffs.tolist(),
        "b": b.coeffs.tolist(),
        "hash_function": "sha3_256"
    }
    secret_params = {
        "mk_enc": encrypted_mk
    }
    server_data = {
        "public_parameters": public_params,
        "secret_parameters": secret_params,
        "users": {}
    }

    with open(SERVER_DATA_FILE, "w") as f:
        json.dump(server_data, f, indent=2)

    return public_params
