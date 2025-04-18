# main.py

from fastapi import FastAPI
from fuzzy_commitment.setup import setup_phase

app = FastAPI()

@app.get("/setup")
def run_setup():
    """
    Setup system-wide RLWE parameters and master key.
    Stores them to server_data.json and returns public parameters.
    """
    public_params = setup_phase()
    return {"message": "Setup complete", "public_parameters": public_params}


# main.py (add this below /setup)

from pydantic import BaseModel
from typing import List
from fuzzy_commitment.registration import register_user

class RegistrationInput(BaseModel):
    ID: str
    biometric_bits: List[int]  # list of 0s and 1s

@app.post("/register")
def register_user_route(payload: RegistrationInput):
    response = register_user(payload.ID, payload.biometric_bits)
    return {
        "message": "Registration complete",
        "smart_card_data": response
    }

# main.py (append below /register)

from fuzzy_commitment.login import login_user

class LoginInput(BaseModel):
    ID: str
    biometric_bits: List[int]

@app.post("/login")
def login_user_route(payload: LoginInput):
    try:
        response = login_user(payload.ID, payload.biometric_bits)
        return response
    except Exception as e:
        return {"error": str(e)}


# main.py (append after /login)

from fuzzy_commitment.authentication import authenticate_user

class AuthInput(BaseModel):
    ID: str
    theta5: str

@app.post("/authenticate")
def authenticate_user_route(payload: AuthInput):
    response = authenticate_user(payload.ID, payload.theta5)
    return response

# main.py (append at the bottom)

from fuzzy_commitment.revocation import revoke_user

class RevokeInput(BaseModel):
    ID: str

@app.post("/revoke")
def revoke_user_route(payload: RevokeInput):
    response = revoke_user(payload.ID)
    return response
