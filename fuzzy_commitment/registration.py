# fuzzy_commitment/registration.py

import numpy as np
import secrets
import time
from she import Rq
from she import RLWE
from fuzzy_commitment.constants import N, Q, T, STD_DEV
from fuzzy_commitment.utils import (
    hash_bytes,
    xor_hash,
    encode_bitstring_to_poly,
    save_json,
    load_json
)

SERVER_FILE = "data/server_data.json"
SMARTCARD_FILE = "data/smart_card_data.json"

def register_user(ID_i: str, biometric_bits: list):
    server_data = load_json(SERVER_FILE)
    pub = server_data["public_parameters"]
    mk = Rq(server_data["secret_parameters"]["mk"], Q)

    ki = [secrets.randbits(1) for _ in range(256)]
    nonce = secrets.token_hex(16)

    xr = biometric_bits
    xr_ki = xr + ki
    assert len(xr_ki) == 512

    x_encoded = encode_bitstring_to_poly(xr_ki, Q)
    x_poly = Rq(x_encoded, Q)

    rlwe = RLWE(n=N, p=Q, t=T, std=STD_DEV)

    t1 = time.perf_counter()
    v_i = rlwe.generate_keys()[0]  # T_Vp
    t2 = time.perf_counter()

    a = Rq(pub["a"], Q)
    b = Rq(pub["b"], Q)

    t3 = time.perf_counter()
    a_vi = a * v_i               # T_Mp1
    w_i = a * v_i                # T_Mp2 (same op again)
    Z_i = w_i * b                # T_Mp3
    t4 = time.perf_counter()

    t5 = time.perf_counter()
    beta_i = a_vi + x_poly       # T_add
    t6 = time.perf_counter()

    beta_i_str = str(beta_i.poly.coeffs.tolist())

    t7 = time.perf_counter()
    ci = hash_bytes("".join(map(str, ki)) + nonce)
    ri = hash_bytes(ci + beta_i_str)
    delta_i = xor_hash(
        hash_bytes(str(w_i.poly.coeffs.tolist())),
        hash_bytes(ID_i + ri)
    )
    e_i = xor_hash(
        hash_bytes(ID_i + str(mk.poly.coeffs.tolist())),
        ri
    )
    t8 = time.perf_counter()

    server_data.setdefault("users", {})[ID_i] = {
        "ri": ri,
        "Zi": Z_i.poly.coeffs.tolist(),
        "beta_i": beta_i.poly.coeffs.tolist(),
        "beta_i_str": beta_i_str,
        "e_i": e_i,
        "s": "system_parameter_placeholder",
        "biometric_bits": biometric_bits,
        "ki": ki
    }
    save_json(SERVER_FILE, server_data)

    smart_card_data = {
        "ID": ID_i,
        "N": nonce,
        "beta_i": beta_i.poly.coeffs.tolist()
    }
    save_json(SMARTCARD_FILE, smart_card_data)

    T_Vp = t2 - t1
    T_Mp = t4 - t3
    T_add = t6 - t5
    T_h = t8 - t7
    T_total = T_Vp + T_Mp + T_add + T_h

    print(f"[Perf] T_total = T_Vp + T_Mp + T_add + T_h = {T_total:.6f} seconds")

    return smart_card_data
