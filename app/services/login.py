import jwt
import os
from datetime import datetime, timedelta, timezone
from app.services.register import get_password_hash


SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Crea un token de acceso JWT.

    Args:
        data (dict): Datos a incluir en el token.
        expires_delta (timedelta, optional): Tiempo de expiración del token.

    Returns:
        str: Token JWT.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=12)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str):
    """
    Decodifica un token de acceso JWT.

    Args:
        token (str): Token JWT a decodificar.

    Returns:
        dict: Datos decodificados del token.

    Raises:
        jwt.ExpiredSignatureError: Si el token ha expirado.
        jwt.InvalidTokenError: Si el token es inválido.
    """
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña coincide con su hash.

    Args:
        plain_password (str): Contraseña en texto plano.
        hashed_password (str): Hash de la contraseña.

    Returns:
        bool: True si las contraseñas coinciden, False en caso contrario.
    """
    return get_password_hash(plain_password) == hashed_password