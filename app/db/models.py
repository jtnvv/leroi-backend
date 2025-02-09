from sqlalchemy import Column, Integer, Float, String, DateTime, ForeignKey
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
    creditos = Column(Integer, nullable=False, default=0)
    proveedor = Column(String, nullable=True, default='local')


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


class CorreosBloqueados(Base):
    __tablename__ = "correos_bloqueados"

    id = Column(Integer, primary_key=True, index=True)
    correo = Column(String, unique=True, nullable=False)
    fecha_bloqueo = Column(DateTime, default=datetime.now(timezone.utc))
    # Contador de intentos fallidos
    intentos_fallidos = Column(Integer, default=0)
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


class PriceRequest(BaseModel):
    amount: int


class Payment(Base):
    __tablename__ = 'compra'

    id_compra = Column(Integer, primary_key=True, index=True)
    cantidad = Column(Integer, index=True, nullable=False)
    valor_usd = Column(Float, index=True, nullable=False)
    fecha_compra = Column(DateTime, index=True, nullable=False,
                          default=datetime.now(timezone.utc))
    id_usuario = Column(ForeignKey("usuario.id_usuario"))
