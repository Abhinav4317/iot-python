# File: fuzzy_commitment/revocation.py

import json
import secrets
import hashlib
import numpy as np
import time
import hmac
from time import perf_counter
from cryptography.fernet import Fernet

from she.Rq import Rq
from fuzzy_commitment.constants import (
    N, Q, T, STD_DEV, HASH_FUNCTION, SERVER_SECRET
)

SERVER_FILE    = "data/server_data.json"
SMARTCARD_FILE = "data/smart_card_data.json"

def load_json(path: str):
    with open(path, "r") as f:
        return json.load(f)

def save_json(path: str, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def hash_bytes(b: bytes) -> str:
    h = hashlib.new(HASH_FUNCTION)
    h.update(b)
    return h.hexdigest()

def xor_hex(h1: str, h2: str) -> str:
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return bytes(x ^ y for x, y in zip(b1, b2)).hex()

def discrete_gaussian_arr(n: int, q: int, std: float):
    """Vectorized discrete Gaussian sampling."""
    arr = np.round(std * np.random.randn(n)).astype(np.int64) % q
    return arr

def revoke_user(ID_i: str, biometric_bits: list):
    """
    Biometric Revocation Phase:
      1) Re-verify user via login (omitted).
      2) Issue fresh RLWE commitment under new key k_i'.
      3) Update server and smart-card data securely.
    """
    # --- Load & decrypt smart-card ---
    server_data = load_json(SERVER_FILE)
    with open(SMARTCARD_FILE, "rb") as f:
        encrypted_blob = f.read()
    smart_card_json = Fernet(SERVER_SECRET).decrypt(encrypted_blob)
    smart_card = json.loads(smart_card_json)
    print(smart_card)
    # --- Pseudonymize ID and load server user entry ---
    pseudonym = hmac.new(
        SERVER_SECRET,
        ID_i.encode(),
        hashlib.sha256
    ).hexdigest()
    user_srv = server_data["users"].get(pseudonym)
    if not user_srv or smart_card.get("ID") != ID_i:
        return {"error": "User not found"}

    # (Ideally re-run login_user’s verification here to authenticate the request.)

    t0 = perf_counter()

    # --- Decrypt master key mk ---
    fernet = Fernet(SERVER_SECRET)
    mk_json = fernet.decrypt(
        server_data["secret_parameters"]["mk_enc"].encode()
    )
    mk_coeffs = json.loads(mk_json)

    # --- 1) Generate new user key bits & nonce ---
    k_i_new     = [secrets.randbits(1) for _ in range(T)]
    N_nonce_new = secrets.token_bytes(16)
    c_i_new     = hash_bytes(bytes(k_i_new) + N_nonce_new)

    # --- 2) Sample fresh RLWE commitments via NumPy ---
    v_arr  = discrete_gaussian_arr(N, Q, STD_DEV)
    e1_arr = discrete_gaussian_arr(N, Q, STD_DEV)
    e2_arr = discrete_gaussian_arr(N, Q, STD_DEV)

    pub = server_data["public_parameters"]
    a_arr = np.array(pub["a"], dtype=np.int64)
    b_arr = np.array(pub["b"], dtype=np.int64)

    # Compute u' = a·v + e1 (negacyclic reduction)
    conv_av = np.polynomial.polynomial.polymul(a_arr, v_arr).astype(np.int64)
    tail_av = np.concatenate([conv_av[N:], np.zeros(1, dtype=np.int64)])
    u_arr   = (conv_av[:N] - tail_av) % Q
    u_arr   = (u_arr + e1_arr) % Q

    # Compute t' = b·v + e2
    conv_bv = np.polynomial.polynomial.polymul(b_arr, v_arr).astype(np.int64)
    tail_bv = np.concatenate([conv_bv[N:], np.zeros(1, dtype=np.int64)])
    t_arr   = (conv_bv[:N] - tail_bv) % Q
    t_arr   = (t_arr + e2_arr) % Q

    # Wrap into Rq elements
    u_new = Rq(u_arr, Q)
    t_new = Rq(t_arr, Q)

    # --- 3) Encode new biometric || key and compute β' ---
    m_bits_new = biometric_bits + k_i_new
    m_poly_new = Rq(m_bits_new + [0] * (N - len(m_bits_new)), Q)
    beta_new   = u_new + m_poly_new

    # --- 4) Compute r_new, δ_new, e_new ---
    r_new = hash_bytes(
        bytes.fromhex(c_i_new) +
        json.dumps(beta_new.coeffs.tolist()).encode()
    )
    delta_new = xor_hex(
        hash_bytes(json.dumps(t_new.coeffs.tolist()).encode()),
        hash_bytes(ID_i.encode() + bytes.fromhex(r_new))
    )
    mk_bytes = json.dumps(mk_coeffs).encode()
    e_new = xor_hex(
        hash_bytes(ID_i.encode() + mk_bytes),
        r_new
    )

    t1 = perf_counter()
    print(f"Time for revocation: {t1 - t0:.6f} seconds")

    # --- 5) Overwrite server entries with replay timestamp ---
    user_srv.update({
        "t":       t_new.coeffs.tolist(),
        "r_i":     r_new,
        "delta_i": delta_new,
        "e_i":     e_new,
        "θ1_ts":   time.time()
    })
    server_data["users"][pseudonym] = user_srv
    # Save encrypted mk remains intact; only user fields changed
    save_json(SERVER_FILE, server_data)

    # --- 6) Overwrite & encrypt smart-card entries ---
    smart_card.update({
        "ID":    pseudonym,
        "N":     N_nonce_new.hex(),
        "beta":  beta_new.coeffs.tolist(),
        "u":     u_new.coeffs.tolist(),
        "k_i":   k_i_new
    })
    card_blob = json.dumps(smart_card).encode()
    with open(SMARTCARD_FILE, "wb") as f:
        f.write(Fernet(SERVER_SECRET).encrypt(card_blob))

    return {"message": f"Biometric for '{ID_i}' successfully revoked"}
