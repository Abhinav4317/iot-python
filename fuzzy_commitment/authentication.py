# File: fuzzy_commitment/authentication.py

import json
import hashlib
from time import perf_counter
import hmac
from she.Rq import Rq
from fuzzy_commitment.constants import (
    Q, HASH_FUNCTION, SYSTEM_PARAMETER_S, SERVER_ID,SERVER_SECRET
)

SERVER_FILE = "data/server_data.json"

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

def authenticate_user(ID_i: str, payload: dict):
    """
    payload includes {theta1, theta2, theta4, theta5, theta6}.
    Returns theta10, theta11, and session_key.
    """
    server_data = load_json(SERVER_FILE)
    pseudonym = hmac.new(SERVER_SECRET, ID_i.encode(), hashlib.sha256).hexdigest()
    user_srv = server_data["users"].get(pseudonym)
    if not user_srv:
        return {"error": "Unknown user"}

    θ1 = payload["theta1"]
    θ2 = payload["theta2"]
    θ4 = payload["theta4"]
    θ5 = payload["theta5"]
    θ6 = payload["theta6"]

    R_s_hex = user_srv.get("R_s", "")
    s       = SYSTEM_PARAMETER_S
    ID_s    = SERVER_ID

    t0 = perf_counter()

    # A1/A2: recover R_u and verify θ5 & θ6
    θ7 = xor_hex(θ2, θ1)                # θ7 = θ2 ⊕ θ1
    R_u = bytes.fromhex(θ7)
    θ3  = hash_bytes(s.encode() + R_u)  # θ3 = H(s ∥ R_u)
    expected_θ6=hash_bytes(s.encode() + ID_i.encode())
    # θ6 should be H(s ∥ ID_i)
    if not hmac.compare_digest(θ6, expected_θ6):
        return {"error": "θ6 (ID proof) mismatch"}

    # verify θ5 = H(θ2 ∥ θ3 ∥ θ4)
    exp5 = hash_bytes(
        bytes.fromhex(θ2) +
        bytes.fromhex(θ3) +
        bytes.fromhex(θ4)
    )
    if not hmac.compare_digest(exp5, θ5):
        return {"error": "θ5 mismatch"}

    # A3: build server’s response
    θ0 = xor_hex(θ4, θ5)  # θ0 = θ4 ⊕ θ5

    # θ10 = H(θ0 ∥ ID_s ∥ s) ⊕ θ5 ⊕ R_s
    h0  = hash_bytes(bytes.fromhex(θ0) + ID_s.encode() + s.encode())
    θ10 = xor_hex(xor_hex(h0, θ5), R_s_hex)

    # θ11 = H(θ1 ∥ θ0 ∥ s ∥ R_s)
    θ11 = hash_bytes(
        bytes.fromhex(θ1) +
        bytes.fromhex(θ0) +
        s.encode() +
        bytes.fromhex(R_s_hex)
    )

    # derive session key: K_sess = H(θ0 ∥ θ6 ∥ R_s ∥ ID_s)
    K_sess = hash_bytes(
        bytes.fromhex(θ0) +
        bytes.fromhex(θ6) +
        bytes.fromhex(R_s_hex) +
        ID_s.encode()
    )

    t1 = perf_counter()
    print(f"Time for authentication: {t1-t0:.6f} seconds")

    # persist θ10, θ11 if desired
    user_srv.update({"theta10": θ10, "theta11": θ11})
    save_json(SERVER_FILE, server_data)

    return {
        "message":     "Authentication successful",
        "theta10":     θ10,
        "theta11":     θ11,
        "session_key": K_sess
    }
