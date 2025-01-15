
from app.services.login import decode_access_token  
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from app.main import app
from app.db.session import SessionLocal
import jwt
from datetime import datetime, timedelta
from app.services.register import get_password_hash
from app.services.login import create_access_token 




def test_register_verify_login(client):
    clean_db() 

    request_data = {
        "name": "Juan",
        "last_name": "Pérez",
        "email": "juan.perez@example.com",
        "password": "password123",
        "provider": "local"
    }

    
    response = client.post("/register", json=request_data)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Usuario registrado correctamente"

    
    request_data = {
        "email": "juan.perez@example.com",
        "code": "123456"
    }

    
    response = client.post("/send-verification", json=request_data)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Código de verificación enviado"
    assert response_data["email"] == "juan.perez@example.com"

    
    request_data = {
        "email": "juan.perez@example.com",
        "code": "123456"
    }

    
    response = client.post("/verify-code", json=request_data)
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Código de verificación correcto"

   
    request_data = {
        "email": "juan.perez@example.com",
        "password": "password123"
    }

   
    response = client.post("/login", json=request_data)
    assert response.status_code == 200
    response_data = response.json()
    assert "access_token" in response_data
    assert response_data["token_type"] == "bearer"

    
    access_token = response_data["access_token"]
    response = client.get("/validate-token", headers={"Authorization": f"Bearer {access_token}"})
    
    
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Token válido"
    assert response_data["data"]["sub"] == "juan.perez@example.com" 


@pytest.fixture()
def client():
    with TestClient(app) as client:
        yield client


def clean_db():
    db = SessionLocal()
    try:
        db.execute(text("DELETE FROM usuario WHERE 1=1"))  # Limpia tabla usuarios
        db.execute(text("DELETE FROM codigos WHERE 1=1"))  # Limpia tabla códigos
        db.commit()
    finally:
        db.close()

# Función para registrar un usuario de Google
def register_google_user():
    db = SessionLocal()
    try:
        db.execute(
            text(
                "INSERT INTO usuario (correo, nombre,apellido, proveedor) VALUES ('google.user@example.com', 'Google User','google', 'google')"
            )
        )
        db.commit()
    finally:
        db.close()

# Test para el endpoint `/login-google`
def test_login_google(client):
    # Asegúrate de que el usuario de Google está registrado
    register_google_user()

    # Datos para iniciar sesión con Google
    request_data = {
        "email": "google.user@example.com",
        "name": "Google User"
    }

    response = client.post("/login-google", json=request_data)

    
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert "access_token" in response_data
    assert response_data["token_type"] == "bearer"


def test_forgot_password(client):
    
    register_google_user()

   
    request_data = {
        "email": "google.user@example.com"
    }

    # Solicitud para solicitar el restablecimiento de contraseña
    response = client.post("/forgot-password", json=request_data)
    
    # Verificaciones del resultado
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Enlace de restablecimiento enviado"
    assert response_data["email"] == "google.user@example.com"



# Función para crear el token de restablecimiento de contraseña
def create_reset_token(email: str, expires_delta: timedelta = timedelta(hours=1)):
    """
    Crea un token de restablecimiento de contraseña.

    Args:
        email (str): Correo electrónico del usuario para asociar al token.
        expires_delta (timedelta, optional): Tiempo de expiración del token (default es 1 hora).

    Returns:
        str: Token JWT para restablecer la contraseña.
    """
    return create_access_token({"sub": email}, expires_delta)


def test_reset_password(client):
    # Asegúrate de que el usuario esté registrado previamente
    register_google_user()

    
    request_data = {
        "email": "google.user@example.com"
    }
    response = client.post("/forgot-password", json=request_data)

    # Verifica que la respuesta sea exitosa
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Enlace de restablecimiento enviado"

    
    reset_token = create_reset_token("google.user@example.com")

   
    request_data = {
        "token": reset_token,
        "new_password": "newpassword123"
    }
    response = client.post("/reset-password", json=request_data)

    
    assert response.status_code == 200
    response_data = response.json()
    assert response_data["status"] == "success"
    assert response_data["message"] == "Contraseña cambiada correctamente"


