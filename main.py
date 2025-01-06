from dotenv import load_dotenv
load_dotenv()

import os
from fastapi import FastAPI, Header, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt, JWTError
from supabase import create_client
from pydantic import BaseModel

url = os.environ.get("SUPABASE_URL")
key = os.environ.get("SUPABASE_KEY")
s_jwt = os.environ.get("SUPABASE_JWT")

supabase = create_client(url, key)
user = None

app = FastAPI()

# origins = [
#     "http://localhost",
#     "http://localhost:3000"
# ]

# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=origins,
#     allow_credentials=True,
#     allow_methods=['*'],
#     allow_headers=['*']
# )

class UserLogin(BaseModel):
    email: str
    password: str

def get_current_user(authorization: str = Header(None)):
    """Dependencia para obtener el usuario actual desde el token JWT"""

    if not authorization:
        raise HTTPException(status_code=401, detail="Autorización requerida")
    
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="Esquema de autorización incorrecto. Debe ser Bearer.")
    except ValueError:
        raise HTTPException(status_code=401, detail="Formato de autorización incorrecto")
    
    try:
        payload = jwt.decode(
            token, s_jwt, algorithms=["HS256"]
        )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="ID de usuario no encontrado en el token")
        return {"id": user_id, **payload}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalido")
    except Exception as e:
        print(f"Error al decodificar el token: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")
    
@app.post("/auth/login")
def login (user_credentials: UserLogin):
    """Endpoint para iniciar sesión"""
    try:
        supabase = create_client(url, key)
        data = supabase.auth.sign_in_with_password({
            "email": user_credentials.email,
            "password": user_credentials.password,
        })
        if data.user:
            return {"access_token": data.session.access_token, "token_type": "bearer"}
        else:
            raise HTTPException(status_code=401, details="Credenciales inválidas")
    except Exception as e:
        print(f"Error durante el inicio de sesión: {e}")
        raise HTTPException(status_code=500, detail="Error interno del servidor")

@app.get("/")
def read_root():
    return {"hello": "world"}

@app.get("/items/", dependencies=[Depends(get_current_user)])
def read_items(current_user: dict = Depends(get_current_user)):
    """Endpoint protegido"""
    return {"message": f"Items para el usuario {current_user['id']}", "items": ["items1", "items2"], "user_data": current_user}

@app.get("/items/open")
def read_items_open():
    """Endpoint público"""
    return {"message": "Este endpoint es público"}