from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.db.models import VerificationCode
import hashlib

def save_verification_code(db: Session, email: str, code: str):
    """
    Guarda un código de verificación en la base de datos.

    Args:
        db (Session): Sesión de la base de datos.
        email (str): Correo electrónico del usuario.
        code (str): Código de verificación.

    """
    expires_at = datetime.utcnow() + timedelta(minutes=5)  
    verification_code = VerificationCode(email=email, codigo=code, expiracion=expires_at)
    db.add(verification_code)
    db.commit()

def verify_code(db: Session, email: str, code: str) -> bool:
    """
    Verifica si un código es válido para un correo dado.

    Args:
        db (Session): Sesión de la base de datos.
        email (str): Correo electrónico del usuario.
        code (str): Código de verificación.

    Returns:
        bool: True si el código es válido, False si no.
    """
    verification_code = db.query(VerificationCode).filter_by(email=email, codigo=code).first()
    if verification_code:
        db.commit()
        return True
    return False

def get_password_hash(password: str) -> str:
    """
    Genera un hash SHA-256 para una contraseña.

    Args:
        password (str): Contraseña a hashear.

    Returns:
        str: Hash de la contraseña.
    """
    return hashlib.sha256(password.encode()).hexdigest()