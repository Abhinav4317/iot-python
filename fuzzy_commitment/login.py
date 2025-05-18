import numpy as np
import time
import secrets
from she import Rq
from fuzzy_commitment.constants import Q, T, N, STD_DEV
from fuzzy_commitment.utils import (
    hash_bytes, xor_hash, encode_bitstring_to_poly, save_json, load_json
)

SERVER_FILE = "data/server_data.json"
SMARTCARD_FILE = "data/smart_card_data.json"

def login_user(ID_i: str, biometric_bits: list):
    server_data = load_json(SERVER_FILE)
    smart_card_data = load_json(SMARTCARD_FILE)

    user_data = server_data["users"].get(ID_i)
    if not user_data:
        raise ValueError("User not registered.")

    beta_i = Rq(user_data["beta_i"], Q)
    beta_i_str = user_data["beta_i_str"]
    ri_stored = user_data["ri"]
    ki = user_data["ki"]
    mk = Rq(server_data["secret_parameters"]["mk"], Q)

    Zi = Rq(user_data["Zi"], Q)
    a = Rq(server_data["public_parameters"]["a"], Q)

    t1 = time.perf_counter()
    w_i_prime = (Zi * a) * mk  
    t2 = time.perf_counter()

    xr_prime = biometric_bits + [0] * 256
    xq_prime = encode_bitstring_to_poly(xr_prime, Q)
    xq_poly = Rq(xq_prime, Q)

    t3 = time.perf_counter()
    beta_q = w_i_prime + xq_poly  
    t4 = time.perf_counter()

    nonce = smart_card_data["N"]

    t5 = time.perf_counter()
    ci_prime = hash_bytes("".join(map(str, ki)) + nonce)
    ri_prime = hash_bytes(ci_prime + beta_i_str)

    if ri_prime != ri_stored:
        return {"message": "Key mismatch. Access denied."}

    e_i = user_data["e_i"]
    ei_xor_ri_prime = xor_hash(e_i, ri_prime)

    Ru = secrets.token_hex(16)
    s = user_data.get("s", "system_param")

    theta1 = ei_xor_ri_prime
    theta2 = xor_hash(theta1, Ru)
    theta3 = hash_bytes(s + Ru)
    theta4 = xor_hash(ci_prime, theta3)
    theta5 = hash_bytes(theta2 + theta3 + theta4)
    theta6 = hash_bytes(s + ID_i)
    t6 = time.perf_counter()

    server_data["users"][ID_i].update({
        "theta1": theta1,
        "theta2": theta2,
        "theta3": theta3,
        "theta4": theta4,
        "theta5": theta5,
        "theta6": theta6
    })
    save_json(SERVER_FILE, server_data)

    smart_card_data.update({
        "theta1": theta1,
        "theta2": theta2,
        "theta3": theta3,
        "theta4": theta4,
        "theta5": theta5,
        "theta6": theta6
    })
    save_json(SMARTCARD_FILE, smart_card_data)
    T_Mp = t2 - t1
    T_add = t4 - t3
    T_h = t6 - t5
    T_total = T_Mp + T_add + T_h

    print(f"[Perf] T_total = T_Mp + T_add + T_h = {T_total:.6f} seconds")

    return {
        "message": "Login successful",
        "smart_card_data": {
            "theta1": theta1,
            "theta2": theta2,
            "theta3": theta3,
            "theta4": theta4,
            "theta5": theta5,
            "theta6": theta6
        }
    }
