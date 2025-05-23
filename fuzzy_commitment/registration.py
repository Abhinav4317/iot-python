import json
import secrets
import hashlib
import numpy as np
from time import perf_counter
from she.Rq import Rq
from fuzzy_commitment.constants import (
    N, Q, T, STD_DEV, HASH_FUNCTION,SERVER_SECRET
)
import hmac
from cryptography.fernet import Fernet

SERVER_DATA_FILE = "data/server_data.json"
SMARTCARD_FILE   = "data/smart_card_data.json"

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)

def hash_bytes(data: bytes) -> str:
    h = hashlib.new(HASH_FUNCTION)
    h.update(data)
    return h.hexdigest()

def xor_hex(h1: str, h2: str) -> str:
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return bytes(x ^ y for x, y in zip(b1, b2)).hex()

def discrete_gaussian_arr(n, q, std):
    arr = np.round(std * np.random.randn(n)).astype(np.int64) % q
    return arr

def register_user(ID_i: str, biometric_bits: list):
    # 0) load server secret & public
    server_data = load_json(SERVER_DATA_FILE)
    pub = server_data["public_parameters"]
    f = Fernet(SERVER_SECRET)
    mk_json = f.decrypt(server_data["secret_parameters"]["mk_enc"].encode())
    mk_coeffs = json.loads(mk_json)

    # wrap public key into Rq
    a = Rq(pub["a"], Q)
    b = Rq(pub["b"], Q)

    # 1) sample RLWE commitment v, u, t via pure NumPy
    t0 = perf_counter()
    # raw arrays
    v_arr  = discrete_gaussian_arr(N, Q, STD_DEV)
    e1_arr = discrete_gaussian_arr(N, Q, STD_DEV)
    e2_arr = discrete_gaussian_arr(N, Q, STD_DEV)

    # a·v and b·v via C-polymul + negacyclic reduction
    conv_av = np.polynomial.polynomial.polymul(a.coeffs, v_arr).astype(np.int64)
    tail_av = np.concatenate([conv_av[N:], np.zeros(1, dtype=np.int64)])
    u_arr = (conv_av[:N] - tail_av) % Q
    u_arr = (u_arr + e1_arr) % Q

    conv_bv = np.polynomial.polynomial.polymul(b.coeffs, v_arr).astype(np.int64)
    tail_bv = np.concatenate([conv_bv[N:], np.zeros(1, dtype=np.int64)])
    t_arr = (conv_bv[:N] - tail_bv) % Q
    t_arr = (t_arr + e2_arr) % Q

    # wrap into Rq for later use
    u      = Rq(u_arr, Q)
    t_poly = Rq(t_arr, Q)

    # 2) generate key bits and nonce
    k_i    = [secrets.randbits(1) for _ in range(T)]
    N_nonce= secrets.token_bytes(16)
    c_i    = hash_bytes(bytes(k_i) + N_nonce)

    # 3) encode biometric||key and compute β = u + m
    m_bits   = biometric_bits + k_i
    m_poly   = Rq(m_bits + [0]*(N-len(m_bits)), Q)  # zero-pad
    beta_poly= u + m_poly
    beta_json= json.dumps(beta_poly.coeffs.tolist()).encode()

    # 4) compute r_i = H(c_i || β)
    r_i = hash_bytes(bytes.fromhex(c_i) + beta_json)

    # 5) δ_i = H(t) ⊕ H(ID||r_i)
    t_json = json.dumps(t_poly.coeffs.tolist()).encode()
    δ_i = xor_hex(
        hash_bytes(t_json),
        hash_bytes(ID_i.encode() + bytes.fromhex(r_i))
    )

    # 6) e_i = H(ID||mk) ⊕ r_i
    mk_json = json.dumps(mk_coeffs).encode()
    e_i = xor_hex(
        hash_bytes(ID_i.encode() + mk_json),
        r_i
    )
    pseudonym = hmac.new(SERVER_SECRET, ID_i.encode(), hashlib.sha256).hexdigest()
    t1 = perf_counter()
    print(f"Time for registration: {t1-t0:.6f} s")

    # 7) persist server state

    server_data["users"][ID_i] = {
        "r_i":    r_i,
        "t":      t_poly.coeffs.tolist(),
        "delta_i": δ_i,
        "e_i":    e_i
    }
    server_data["users"][pseudonym] = server_data["users"].pop(ID_i)
    save_json(SERVER_DATA_FILE, server_data)

    # 8) build smart card
    smart_card = {
        "ID":   ID_i,
        "N":    N_nonce.hex(),
        "beta": beta_poly.coeffs.tolist(),
        "u":    u.coeffs.tolist(),
        "k_i":  k_i
    }
    
    save_json(SMARTCARD_FILE, smart_card)
    smart_blob = json.dumps(smart_card).encode()
    with open(SMARTCARD_FILE, "wb") as f_s:
        f_s.write(Fernet(SERVER_SECRET).encrypt(smart_blob))

    return smart_card
