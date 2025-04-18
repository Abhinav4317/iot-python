# fuzzy_commitment/authentication.py

import time
from fuzzy_commitment.utils import load_json, hash_bytes

SERVER_FILE = "data/server_data.json"
SMARTCARD_FILE = "data/smart_card_data.json"

def authenticate_user(ID_i: str, theta5_from_user: str):
    server_data = load_json(SERVER_FILE)
    smart_card_data = load_json(SMARTCARD_FILE)

    user_data = server_data["users"].get(ID_i)
    if not user_data:
        return {"message": "Authentication failed. Unknown user."}

    # Step A2: MS verifies θ5
    theta2 = user_data["theta2"]
    theta3 = user_data["theta3"]
    theta4 = user_data["theta4"]

    t1 = time.perf_counter()
    expected_theta5 = hash_bytes(theta2 + theta3 + theta4)
    t2 = time.perf_counter()

    if expected_theta5 != theta5_from_user:
        return {"message": "Authentication failed. Invalid θ5."}

    # Step A3: Return θ6
    theta6 = user_data["theta6"]

    T_h = t2 - t1
    T_total = T_h

    print(f"[Perf] T_total = T_h = {T_total:.6f} seconds")

    return {
        "message": "Mutual authentication successful.",
        "theta6": theta6
    }
