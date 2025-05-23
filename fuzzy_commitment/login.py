import json
import hashlib
import secrets
from time import perf_counter
from she.Rq import Rq
from fuzzy_commitment.constants import (
    N, Q, T, STD_DEV, HASH_FUNCTION, HAMMING_THRESHOLD, SYSTEM_PARAMETER_S,SERVER_SECRET,SESSION_TIMEOUT
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

def hash_bytes(b: bytes) -> str:
    h = hashlib.new(HASH_FUNCTION)
    h.update(b)
    return h.hexdigest()

def xor_hex(h1: str, h2: str) -> str:
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return bytes(x ^ y for x, y in zip(b1, b2)).hex()

def hamming_distance(a, b):
    return sum(x != y for x, y in zip(a, b))

def login_user(ID_i: str, biometric_bits: list):
    # 1) load state
    srv = load_json(SERVER_DATA_FILE)
    blob = open(SMARTCARD_FILE,"rb").read()
    card = json.loads(Fernet(SERVER_SECRET).decrypt(blob))
    pseudonym = hmac.new(SERVER_SECRET, ID_i.encode(), hashlib.sha256).hexdigest()
    user  = srv["users"].get(pseudonym)
    if not user:
        raise ValueError("User not registered")

    # unpack
    N_nonce    = bytes.fromhex(card["N"])
    u_arr      = card["u"]
    beta_arr   = card["beta"]
    k_i        = card["k_i"]

    r_i_stored = user["r_i"]
    t_coeffs   = user["t"]
    δ_i        = user["delta_i"]
    e_i        = user["e_i"]

    t0 = perf_counter()

    # reconstruct Rq
    a = Rq(srv["public_parameters"]["a"], Q)
    u = Rq(u_arr, Q)
    beta = Rq(beta_arr, Q)
    t_poly = Rq(t_coeffs, Q)

    # 2) validate δ_i
    h_t   = hash_bytes(json.dumps(t_coeffs).encode())
    h_IDr = hash_bytes(ID_i.encode() + bytes.fromhex(r_i_stored))
    if not hmac.compare_digest(δ_i, xor_hex(h_t, h_IDr)):
        return {"error": "Commitment validation failed"}

    # 3) recover m = β - u
    m_poly = beta + (Rq([-c for c in u.coeffs], Q))
    m_bits = m_poly.coeffs.tolist()[:len(biometric_bits)+T]
    x_r_prime = m_bits[:len(biometric_bits)]
    k_prime   = m_bits[len(biometric_bits):]

    # 4) biometric match
    if hamming_distance(biometric_bits, x_r_prime) > HAMMING_THRESHOLD:
        return {"error": "Biometric mismatch"}

    # 5) key & r_i check
    c_i = hash_bytes(bytes(k_i) + N_nonce)
    r_i_prime = hash_bytes(bytes.fromhex(c_i) + json.dumps(beta_arr).encode())
    if r_i_prime != r_i_stored:
        return {"error": "Key mismatch"}

    # 6) compute θs
    θ1 = xor_hex(e_i, r_i_prime)
    R_u = secrets.token_bytes(16)
    θ2 = xor_hex(θ1, R_u.hex())
    θ3 = hash_bytes(SYSTEM_PARAMETER_S.encode() + R_u)
    θ4 = xor_hex(c_i, θ3)
    θ5 = hash_bytes(bytes.fromhex(θ2) + bytes.fromhex(θ3) + bytes.fromhex(θ4))
    θ6 = hash_bytes(SYSTEM_PARAMETER_S.encode() + ID_i.encode())

    # 7) persist and respond
    import time
    now = time.time()
    last_ts = user.get("θ1_ts", 0)
    if now - last_ts > SESSION_TIMEOUT:
        user["θ1_ts"] = now
    else:
        return {"error": "Replay detected"}

    user.update({"theta1": θ1, "theta2": θ2, "theta4": θ4, "theta5": θ5, "theta6": θ6})
    user["R_s"] = secrets.token_bytes(16).hex()
    save_json(SERVER_DATA_FILE, srv)

    t1 = perf_counter()
    print(f"Time for login: {t1-t0:.6f} s")

    return {
        "message": "Login step 1 successful",
        "response": {
            "t":        t_coeffs,
            "R_s":      user["R_s"],
            "theta1":   θ1,
            "theta2":   θ2,
            "theta4":   θ4,
            "theta5":   θ5,
            "theta6":   θ6
        }
    }
