# fuzzy_commitment/revocation.py

import time
from fuzzy_commitment.utils import load_json, save_json

SERVER_FILE = "data/server_data.json"
SMARTCARD_FILE = "data/smart_card_data.json"

def revoke_user(ID_i: str):
    server_data = load_json(SERVER_FILE)

    if ID_i not in server_data.get("users", {}):
        return {"message": f"User '{ID_i}' not found."}

    t1 = time.perf_counter()

    # Step Rv1: Mark user as revoked
    server_data["users"][ID_i]["revoked"] = True

    # Step Rv3: Remove or flag smart card data
    smart_card_data = load_json(SMARTCARD_FILE)
    if smart_card_data.get("ID") == ID_i:
        smart_card_data["revoked"] = True

    # Save updates
    save_json(SERVER_FILE, server_data)
    save_json(SMARTCARD_FILE, smart_card_data)

    t2 = time.perf_counter()
    T_add = t2 - t1
    T_total = T_add

    print(f"[Perf] T_total = T_add = {T_total:.6f} seconds")

    return {
        "message": f"Biometric credentials for '{ID_i}' successfully revoked.",
        "revoked_user": ID_i
    }
