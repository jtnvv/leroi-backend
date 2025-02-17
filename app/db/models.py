from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, func
from .session import Base
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime, timezone


class EmailCheckRequest(BaseModel):
    email: EmailStr


class EmailVerificationRequest(BaseModel):
    email: EmailStr
    code: str


class UserRegistrationRequest(BaseModel):
    name: str
    last_name: Optional[str] = None
    email: EmailStr
    password: Optional[str] = None
    provider: str


class User(Base):
    __tablename__ = 'usuario'

    id_usuario = Column(Integer, primary_key=True, index=True)
    nombre = Column(String, index=True, nullable=False)
    apellido = Column(String, index=True, nullable=False)
    correo = Column(String, index=True, nullable=False)
    contraseña = Column(String, nullable=True)
    proveedor = Column(String, nullable=True, default='local')
    creditos = Column(Integer, nullable=False, default=0)


class VerificationCode(Base):
    __tablename__ = 'codigos'

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True, nullable=False)
    codigo = Column(String, nullable=False)
    expiracion = Column(DateTime, nullable=False)


class LoginRequest(BaseModel):
    email: EmailStr
    password: Optional[str] = None
    name: Optional[str] = None


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


class PriceRequest(BaseModel):
    amount: int


class PaymentRequest(BaseModel):
    amount: int

class CorreosBloqueados(Base):
    __tablename__ = "correos_bloqueados"

    id = Column(Integer, primary_key=True, index=True)
    correo = Column(String, unique=True, nullable=False)
    fecha_bloqueo = Column(DateTime, default=datetime.now(timezone.utc))
    intentos_fallidos = Column(Integer, default=0)  # Contador de intentos fallidos
    bloqueado_hasta = Column(DateTime, nullable=True)  
    correos_login = Column(String, nullable=True)


class ProcessFileRequest(BaseModel):
    fileName: str
    fileType: str
    fileSize: int
    fileBase64: str

class UserUpdateRequest(BaseModel):
    name: str
    last_name: str
    provider: Optional[str]
    email: Optional[str]
    
class TopicRequest(BaseModel):
    topic: str

class Roadmap(Base):
    __tablename__ = "roadmap" 

    id_roadmap = Column(Integer, primary_key=True, index=True, autoincrement=True)
    nombre = Column(String, nullable=False)  # Nombre del roadmap
    fecha_creacion = Column(DateTime, default=func.now())  # Fecha de creación automática
    id_usuario_creador = Column(Integer, ForeignKey("usuario.id_usuario"), nullable=False)  # ID del usuario creador
    prompt = Column(String, nullable=False)  # Respuesta de Gemini (cadena de texto)