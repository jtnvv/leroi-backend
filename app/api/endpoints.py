# app/api/endpoints.py
from fastapi import APIRouter, Depends, HTTPException
from fastapi_mail import MessageSchema
from app.core.email import fastmail
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.services.register import save_verification_code, verify_code, get_password_hash
from app.db.models import EmailVerificationRequest, UserRegistrationRequest, User

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
 
@router.post("/send-verification")
async def send_verification_email(request: EmailVerificationRequest, db: Session = Depends(get_db)):
    try:
        save_verification_code(db, request.email, request.code)
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
    if verify_code(db, request.email, request.code):
        return {"status": "success", "message": "Código de verificación correcto"}
    else:
        raise HTTPException(
            status_code=400,
            detail="Código de verificación incorrecto o expirado"
        )
        
@router.post("/register")
async def register_user(request: UserRegistrationRequest, db: Session = Depends(get_db)):
    hashed_password = get_password_hash(request.password) if request.password else None
    user = User(
        nombre=request.name, 
        apellido=request.last_name if request.last_name else '', 
        correo=request.email, 
        contraseña=hashed_password,
        proveedor=request.provider 
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"status": "success", "message": "Usuario registrado correctamente"}