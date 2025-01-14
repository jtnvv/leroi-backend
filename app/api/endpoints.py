import jwt
import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi_mail import MessageSchema
from app.core.email import fastmail
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.services.register import save_verification_code, verify_code, get_password_hash
from app.db.models import (
    EmailVerificationRequest, 
    UserRegistrationRequest, 
    User, 
    LoginRequest, 
    EmailCheckRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest
)
from app.services.login import create_access_token, decode_access_token, verify_password
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
FRONTEND_URL = os.getenv("FRONTEND_URL")

def get_db():
    """
    Proporciona una sesión de base de datos para cada solicitud.

    Yields:
        Session: Sesión de la base de datos.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
# REGISTER

@router.post("/check-email")
async def check_email(request: EmailCheckRequest, db: Session = Depends(get_db)):
    """
    Verifica si un correo ya existe en la base de datos.

    Args:
        email (str): Correo electrónico a verificar.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y si el correo existe.
    """
    user = db.query(User).filter_by(correo=request.email).first()
    return {"status": "success", "exists": user is not None}

@router.post("/send-verification")
async def send_verification_email(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    """
    Envía un correo electrónico de verificación al usuario.

    Args:
        request (EmailVerificationRequest): Datos del correo y código de verificación.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y mensaje de éxito.

    Raises:
        HTTPException: Si ocurre un error al enviar el correo.
    """
    try:
        # Guarda el código de verificación en la base de datos
        save_verification_code(db, request.email, request.code)
        
        # Configura el mensaje de correo electrónico
        message = MessageSchema(
            subject="Verificación de Correo - LEROI",
            recipients=[request.email],
            body=f"""
                <html>
                    <body style="font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 40px;">
                        <h1 style="font-size: 30px; font-weight: bold; color: #ffb923;">Código de Verificación</h1>
                        <p style="font-size: 20px; color: #000000;">Tu código de verificación es:</p>
                        <h2 style="font-size: 40px; color: #835bfc;">{request.code}</h2>
                        <p style="font-size: 16px; color: #000000;">Este código expirará en 5 minutos.</p>
                        <p style="font-size: 16px; color: #000000;">Si no solicitaste este código, puedes ignorar este correo.</p>
                    </body>
                </html>
            """,
            subtype="html"
        )
        
        # Envía el mensaje de correo electrónico
        await fastmail.send_message(message)
        
        return {
            "status": "success",
            "message": "Código de verificación enviado",
            "email": request.email
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al enviar el email: {str(e)}"
        )

@router.post("/verify-code")
async def verify_code_endpoint(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    """
    Verifica el código de verificación proporcionado por el usuario.

    Args:
        request (EmailVerificationRequest): Datos del correo y código de verificación.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y mensaje de éxito si el código es correcto.

    Raises:
        HTTPException: Si el código es incorrecto o ha expirado.
    """
    if verify_code(db, request.email, request.code):
        return {"status": "success", "message": "Código de verificación correcto"}
    else:
        raise HTTPException(
            status_code=400,
            detail="Código de verificación incorrecto o expirado"
        )

@router.post("/register")
async def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    """
    Registra un nuevo usuario en la base de datos.

    Args:
        request (UserRegistrationRequest): Datos del usuario a registrar.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y mensaje de éxito tras el registro.
    """
    
    # Hashea la contraseña si está presente
    hashed_password = get_password_hash(request.password) if request.password else None
    
    # Crea un nuevo objeto de usuario
    user = User(
        nombre=request.name, 
        apellido=request.last_name if request.last_name else '', 
        correo=request.email, 
        contraseña=hashed_password,
        proveedor=request.provider 
    )
    
    # Añade el usuario a la base de datos
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {"status": "success", "message": "Usuario registrado correctamente"}

# LOGIN

@router.post("/login-google")
async def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Inicia sesión de un usuario existente.
    """
    user = db.query(User).filter_by(correo=request.email).first()
    if not user:
        user = User(
            nombre=request.name, 
            apellido='', 
            correo=request.email, 
            contraseña=None,
            proveedor="google"
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        
    access_token = create_access_token(data={"sub": user.correo})
        
    return {"status": "success", "access_token": access_token, "token_type": "bearer"}

@router.post("/login")
async def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    """
    Autentica al usuario y devuelve un token de acceso.

    Args:
        request (LoginRequest): Datos de inicio de sesión del usuario.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Token de acceso y tipo de token.

    Raises:
        HTTPException: Si las credenciales son incorrectas.
    """
    user = db.query(User).filter_by(correo=request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if user.proveedor == "google":
        raise HTTPException(status_code=401, detail="Ya has iniciado sesión con Google")
    if not verify_password(request.password, user.contraseña):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    access_token = create_access_token(data={"sub": user.correo})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/validate-token")
async def validate_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Valida el token de acceso.

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales de autorización.

    Returns:
        dict: Estado de validación del token.
    """
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        return {"status": "success", "message": "Token válido", "data": payload}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")
    
# Endpoint para solicitar el restablecimiento de contraseña
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """
    Envía un enlace de restablecimiento de contraseña al correo del usuario.

    Args:
        request (ForgotPasswordRequest): Datos de la solicitud que contiene el correo electrónico.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y mensaje de éxito si el correo fue enviado.

    Raises:
        HTTPException: Si el usuario no es encontrado o si ocurre un error al enviar el correo.
    """
    # Busca al usuario por correo electrónico
    user = db.query(User).filter_by(correo=request.email).first()
    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    
    try:
        # Genera un token de restablecimiento con una expiración de 1 hora
        reset_token = create_access_token(data={"sub": user.correo}, expires_delta=timedelta(minutes=10))
        
        # Crea el enlace de restablecimiento de contraseña
        reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        
        # Configura el mensaje de correo electrónico
        message = MessageSchema(
            subject="Restablecimiento de Contraseña - LEROI",
            recipients=[request.email],
            body=f"""
                <html>
                    <body style="font-family: Arial, sans-serif; text-align: center; margin: 0; padding: 40px;">
                        <h1 style="font-size: 30px; font-weight: bold; color: #ffb923;">Restablecimiento de Contraseña</h1>
                        <p style="font-size: 20px; color: #000000;">Haz clic en el enlace para restablecer tu contraseña:</p>
                        <a href="{reset_link}" style="font-size: 20px; color: #835bfc;">Restablecer Contraseña</a>
                        <p style="font-size: 16px; color: #000000;">Este enlace expirará en 10 minutos.</p>
                        <p style="font-size: 16px; color: #000000;">Si no solicitaste este cambio, puedes ignorar este correo.</p>
                    </body>
                </html>
            """,
            subtype="html"
        )
        
        # Envía el mensaje de correo electrónico
        await fastmail.send_message(message)
        
        return {
            "status": "success",
            "message": "Enlace de restablecimiento enviado",
            "email": request.email
        }
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al enviar el email: {str(e)}"
        )

# Endpoint para restablecer la contraseña usando el token
@router.post("/reset-password")
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    """
    Restablece la contraseña del usuario usando un token de restablecimiento.

    Args:
        request (ResetPasswordRequest): Datos de la solicitud que contiene el token y la nueva contraseña.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Estado y mensaje de éxito si la contraseña fue cambiada.

    Raises:
        HTTPException: Si el token es inválido, ha expirado, o si el usuario no es encontrado.
    """
    try:
        # Decodifica el token para obtener el correo electrónico
        payload = jwt.decode(request.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=400, detail="Token inválido")
        
        # Busca al usuario por correo electrónico
        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Cambia la contraseña del usuario
        user.contraseña = get_password_hash(request.new_password)
        db.commit()
        
        return {"status": "success", "message": "Contraseña cambiada correctamente"}
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido")