from fastapi import FastAPI
from fuzzy_commitment.setup import setup_phase

app = FastAPI()

@app.get("/setup")
def run_setup():
    public_params=setup_phase()
    return {"message": "Setup complete", "public_parameters": public_params}

# — registration endpoint
from pydantic import BaseModel
from typing import List
from fuzzy_commitment.registration import register_user

class RegistrationInput(BaseModel):
    ID: str
    biometric_bits: List[int]

@app.post("/register")
def register_user_route(payload: RegistrationInput):
    data = register_user(payload.ID, payload.biometric_bits)
    return {"message": "Registration complete", "smart_card_data": data}

# — login endpoint
from fuzzy_commitment.login import login_user

class LoginInput(BaseModel):
    ID: str
    biometric_bits: List[int]

@app.post("/login")
def login_user_route(payload: LoginInput):
    return login_user(payload.ID, payload.biometric_bits)

# — authenticate endpoint
from fuzzy_commitment.authentication import authenticate_user

class AuthInput(BaseModel):
    ID: str
    theta1: str
    theta2: str
    theta4: str
    theta5: str
    theta6: str

@app.post("/authenticate")
def authenticate_user_route(payload: AuthInput):
    theta_payload = {
        "theta1": payload.theta1,
        "theta2": payload.theta2,
        "theta4": payload.theta4,
        "theta5": payload.theta5,
        "theta6": payload.theta6,
    }
    return authenticate_user(payload.ID, theta_payload)

# — revocation endpoint
from fuzzy_commitment.revocation import revoke_user

class RevokeInput(BaseModel):
    ID: str
    biometric_bits: List[int]

@app.post("/revoke")
def revoke_user_route(payload: RevokeInput):
    return revoke_user(payload.ID, payload.biometric_bits)
