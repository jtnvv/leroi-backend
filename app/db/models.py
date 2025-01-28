from sqlalchemy import Column, Integer, String, DateTime
from .session import Base
from pydantic import BaseModel, EmailStr
from typing import Optional


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

class ProcessFileRequest(BaseModel):
    fileName: str
    fileType: str
    fileSize: int
    fileBase64: str
