import jwt
import os
import base64
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Form, Request
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
    ResetPasswordRequest,
    PriceRequest,
    CorreosBloqueados,
    ProcessFileRequest,
    UserUpdateRequest,
    TopicRequest, 
    Roadmap,
    RoadmapImageRequest,
    Payment
)
from app.services.login import create_access_token, decode_access_token, verify_password
from app.services.pricing import calculate_price
from app.services.ai import ask_gemini, count_tokens_gemini
from app.services.roadmap import price_roadmap
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta
import mercadopago
import httpx
import asyncio
from typing import Dict
from datetime import datetime, timedelta, timezone
import json

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
FRONTEND_URL = os.getenv("FRONTEND_URL")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")

BACKEND_URL = os.getenv("BACKEND_URL")

sdk = mercadopago.SDK(MP_ACCESS_TOKEN)


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
    # Impedir el registro por bloqueo
    blocked_email = db.query(CorreosBloqueados).filter(
        CorreosBloqueados.correo == request.email).first()
    if blocked_email:
        raise HTTPException(
            status_code=400, detail="Este correo está bloqueado y no puede registrarse.")
    # Impedir el registro por bloqueo
    blocked_email = db.query(CorreosBloqueados).filter(
        CorreosBloqueados.correo == request.email).first()
    if blocked_email:
        raise HTTPException(
            status_code=400, detail="Este correo está bloqueado y no puede registrarse.")
    # Hashea la contraseña si está presente
    hashed_password = get_password_hash(
        request.password) if request.password else None

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

# Login normal

MAX_ATTEMPTS = 5
BLOCK_TIME = timedelta(minutes=15)


@router.post("/login")
async def login_user(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(correo=request.email).first()

    if not user:
        raise HTTPException(status_code=401, detail="Usuario no encontrado")
    if user.proveedor == "google":
        raise HTTPException(
            status_code=401, detail="Ya has iniciado sesión con Google")

    blocked_user = db.query(CorreosBloqueados).filter_by(
        correos_login=request.email).first()

    if blocked_user:
        if blocked_user.bloqueado_hasta and blocked_user.bloqueado_hasta.replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):

            raise HTTPException(
                status_code=403, detail="Tu cuenta está bloqueada temporalmente. Intenta más tarde.")

    if not verify_password(request.password, user.contraseña):

        if not blocked_user:
            blocked_user = CorreosBloqueados(
                correos_login=request.email, correo=request.email, intentos_fallidos=1)
            db.add(blocked_user)
        else:
            blocked_user.intentos_fallidos += 1

        if blocked_user.intentos_fallidos >= MAX_ATTEMPTS:
            blocked_user.bloqueado_hasta = datetime.now(
                timezone.utc) + BLOCK_TIME
            db.commit()
            raise HTTPException(
                status_code=403, detail="Tu cuenta ha sido bloqueada temporalmente debido a intentos fallidos.")
        db.commit()
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")
    if blocked_user:
        db.delete(blocked_user)
        db.commit()

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
        reset_token = create_access_token(
            data={"sub": user.correo}, expires_delta=timedelta(minutes=10))

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
                        <p style="font-size: 20px; color: #000000;">Haz clic en el enlace para restablecer tu contraseña:</p><a href=" {reset_link} " style="font-size: 20px; color: #835bfc;">Restablecer Contraseña</a>
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
            raise HTTPException(
                status_code=404, detail="Usuario no encontrado")

        # Cambia la contraseña del usuario
        user.contraseña = get_password_hash(request.new_password)
        db.commit()

        return {"status": "success", "message": "Contraseña cambiada correctamente"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El token ha expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido")


@router.post("/price")
async def price(request: PriceRequest):
    """
    Consultar el valor en dolares de los creditos

    Args:
        request (PriceRequest): Datos de los creditos que se desean comprar.

    Returns:
        dict: Estado y valor de los creditos en dolares

    Raises:
        HTTPException: Si la cantidad de creditos es menor o igual que 0.
    """
    try:
        if request.amount <= 0:
            raise HTTPException(
                status_code=400, detail="La cantidad de créditos debe ser mayor a 0"
            )
        price = calculate_price(request.amount)
        return {"status": "success", "costo": price}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/create-payment/{amount}")
async def create_payment(amount: str, credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """
    Inicia un pago usando la API de MercadoPago.

    Args:
        request (PaymentRequest): Datos del pago enviados desde el frontend.

    Returns:
        dict: URL para redirigir al usuario.
    """
    token = credentials.credentials
    try:
        # Decodificar el token para obtener el correo del usuario
        print(f"Token: {token}")
        print(f"Credentials: {credentials}")
        payload = decode_access_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")

        # Buscar al usuario por correo
        user = db.query(User).filter_by(correo=email).first()

        if not user:
            raise HTTPException(
                status_code=404, detail="Usuario no encontrado"
            )

        # Datos del pago
        id_usuario = user.id_usuario
        u_price = calculate_price(int(amount))

        preference_data = {
            "items": [
                {
                    "id": 1,
                    "title": f"Compra de {amount} creditos - Leroi",
                    "quantity": 1,
                    "unit_price": u_price,
                    "currency_id": "USD",
                }
            ],
            "payer": {
                "name": "John",
                "surname": "Doe",
                "email": "john@doe.com",
            },
            "back_urls": {
                "success": "localhost:5173"
                # "failure": "localhost:5173/order-failed",
                # "pending": "localhost:5173/pending"
            },
            "external_reference": {
                "id_usuario": id_usuario,
                "cantidad": amount,
                "precio": u_price,
            },
            "auto_return": "approved",
            "notification_url": BACKEND_URL + "/mercadopago/paymentNotification"
        }
        # Crear el pago
        preference_response = sdk.preference().create(preference_data)
        preference = preference_response["response"]
        # Retornar la URL de aprobación para redirigir al usuario
        payment_url = preference.get("init_point")

        return {"payment_url": payment_url}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/mercadopago/paymentNotification")
async def payment_listener(request: Request, db: Session = Depends(get_db)):
    """
    Endpoint para recibir notificaciones de pago de MercadoPago.

    Args:
        request (PaymentRequest): Datos enviados desde MercadoPago.

    Returns:
        status: 200 (En caso de que todo esté bien)
        status: diferente de 200 (En caso de que exista algún error)

    """
    try:
        # Obtener el cuerpo de la solicitud
        body = await request.json()

        # Determinar el tipo de notificación
        topic = body.get("topic") or body.get("type")
        if topic == "merchant_order":
            return {"status": "received"}  # Ignorar y responder con 200 OK

        # Obtener el ID de pago si es una notificación de "payment"
        payment_id = body.get("data", {}).get("id") or body.get("id")

        if not payment_id:
            return {"status": "error", "message": "ID de pago no encontrado"}, 400

        # Intentamos obtener los detalles del pago
        payment = sdk.payment().get(payment_id).get("response")

        if not payment:
            return {"status": "error", "message": "Pago no encontrado"}, 400

        # Verificamos si el pago fue aprobado
        if payment.get("status") == "approved":
            print(f"Pago aprobado: ID={payment_id}")
            external_reference = json.loads(payment.get('external_reference'))

            # Extraer información de la transacción
            cantidad = int(external_reference.get("cantidad"))
            valor_precio = float(external_reference.get("precio"))
            id_usuario = int(external_reference.get("id_usuario"))
            fecha_compra = datetime.now()

            # Crear un nuevo objeto de compra
            compra = Payment(
                cantidad=cantidad,
                valor_usd=valor_precio,
                fecha_compra=fecha_compra,
                id_usuario=id_usuario
            )

            db.add(compra)

            # Actualización de creditos del usuario
            # Obtener el usuario
            usuario = db.query(User).filter_by(id_usuario=id_usuario).first()
            if not usuario:
                print(f"Usuario con ID {id_usuario} no encontrado.")
                return {"status": "error", "message": "Usuario no encontrado"}, 200

            usuario.creditos += cantidad

            # Añadir la transacción a la base de datos

            db.commit()
            db.refresh(compra)
            db.refresh(usuario)
            # print("Transacción registrada exitosamente.")

        return {"status": "success", "message": "Notificación procesada correctamente"}

    except Exception as e:
        print(f"Error procesando el webhook: {str(e)}")
        return {"status": "error", "message": str(e)}, 500


# Analisis De Malware
API_KEY = os.getenv("API_KEY")
UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
HEADERS = {
    "x-apikey": API_KEY
}


async def fetch_analysis(analysis_url: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(analysis_url, headers=HEADERS)
        response.raise_for_status()
        return response.json()


@router.post("/analyze/")
async def analyze_file(
    file: UploadFile = File(...),
    email: str = Form(...),
    db: Session = Depends(get_db)
) -> Dict:
    """
    Analiza un archivo PDF en busca de virus y, si se encuentra alguno, elimina al usuario asociado y bloquea su correo.
    """
    if not API_KEY:
        raise HTTPException(status_code=400, detail="API Key is missing")

    # if file.content_type != "application/pdf":
     #  raise HTTPException(status_code=400, detail="Solo se permite subir archivos PDF")

    try:
        file_content = await file.read()

        async with httpx.AsyncClient() as client:
            upload_response = await client.post(UPLOAD_URL, headers=HEADERS, files={"file": (file.filename, file_content)})

        if upload_response.status_code == 200:
            result = upload_response.json()
            analysis_id = result["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            max_attempts = 30
            interval = 5

            for attempt in range(max_attempts):
                analysis_data = await fetch_analysis(analysis_url)

                if analysis_data["data"]["attributes"]["status"] == "completed":
                    stats = analysis_data["data"]["attributes"]["stats"]
                    malicious = stats.get("malicious", 0)
                    harmless = stats.get("harmless", 0)
                    undetected = stats.get("undetected", 0)
                    total = harmless + malicious + undetected

                    has_virus = malicious > 0

                    if has_virus:
                        # Eliminar usuario y bloquear correo si tiene virus
                        user = db.query(User).filter(
                            User.correo == email).first()
                        if user:
                            db.delete(user)
                            db.commit()

                            blocked_email = CorreosBloqueados(
                                correo=email, fecha_bloqueo=datetime.now(timezone.utc))
                            db.add(blocked_email)
                            db.commit()

                        return {
                            "filename": file.filename,
                            "malicious_count": malicious,
                            "total_engines": total,
                            "has_virus": has_virus,
                            "message": "Este archivo tiene virus. El usuario ha sido eliminado y no puede volver a registrarse."
                        }
                    else:
                        return {
                            "filename": file.filename,
                            "malicious_count": malicious,
                            "total_engines": total,
                            "has_virus": has_virus,
                            "message": "Este archivo es seguro"
                        }
                await asyncio.sleep(interval)
            raise HTTPException(
                status_code=408, detail="El análisis no se completó en el tiempo esperado.")
        else:
            raise HTTPException(
                status_code=upload_response.status_code, detail=upload_response.json())
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# View user profile

@router.get("/user-profile")
async def get_user_profile(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Devuelve los datos del perfil del usuario autenticado.

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales de autorización.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Datos del usuario.
    """
    token = credentials.credentials

    try:
        # Decodificar el token para obtener el correo del usuario
        payload = decode_access_token(token)
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")

        # Buscar al usuario por correo
        user = db.query(User).filter_by(correo=email).first()

        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        # Obtener el número de roadmaps creados por el usuario
        roadmaps_count = db.query(Roadmap).filter_by(id_usuario_creador=user.id_usuario).count()

        # Preparar la respuesta con los datos del usuario
        return {
            "status": "success",
            "data": {
                "firstName": user.nombre,
                "lastName": user.apellido,
                "email": user.correo,
                "credits": user.creditos,
                "roadmapsCreated": roadmaps_count, 
                "provider": user.proveedor,
            },
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")

@router.get("/user-roadmaps")
async def get_user_roadmaps(
    credentials: HTTPAuthorizationCredentials = Depends(security),  # Extrae el token
    db: Session = Depends(get_db),
):
    """
    Devuelve los roadmaps creados por el usuario autenticado.

    Args:
        credentials (HTTPAuthorizationCredentials): Credenciales de autorización.
        db (Session): Sesión de la base de datos.

    Returns:
        dict: Lista de roadmaps del usuario.
    """
    token = credentials.credentials  # Obtiene el token de las credenciales

    try:
        # Decodificar el token para obtener el correo del usuario
        payload = decode_access_token(token)
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")

        # Buscar al usuario por correo
        user = db.query(User).filter_by(correo=email).first()

        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        # Obtener los roadmaps del usuario
        roadmaps = db.query(Roadmap).filter_by(id_usuario_creador=user.id_usuario).all()
        

        # Preparar la respuesta con los roadmaps
        return {
            "status": "success",
            "data": [
                {
                    "id_roadmap": roadmap.id_roadmap,
                    "nombre": roadmap.nombre,
                    "fecha_creacion": roadmap.fecha_creacion,
                    "prompt": roadmap.prompt,
                    "image": roadmap.image_base64,
                }
                for roadmap in roadmaps
            ],
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


@router.delete("/delete-user/{email}")
async def delete_user(
    email: str,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    """
    Eliminar un usuario y sus roadmaps asociados.
    """
    token = credentials.credentials

    try:
        payload = decode_access_token(token)
        authenticated_email = payload.get("sub")
        user_role = payload.get("role")

        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Invalid token")

        if user_role != "admin" and authenticated_email != email:
            raise HTTPException(status_code=403, detail="Unauthorized action")

        # Buscar usuario en la base de datos
        user_to_delete = db.query(User).filter_by(correo=email).first()
        if not user_to_delete:
            raise HTTPException(status_code=404, detail="User not found")

        # Eliminar los roadmaps del usuario antes de eliminarlo
        db.query(Roadmap).filter(Roadmap.id_usuario_creador == user_to_delete.id_usuario).delete(synchronize_session=False)

        # Eliminar usuario
        db.delete(user_to_delete)
        db.commit()

        return {
            "status": "success",
            "message": "User deleted successfully",
            "deleted_user_email": email
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        db.rollback()
        print(f"Error al borrar usuario: {e}")  # 👈 Imprime el error en consola
        raise HTTPException(status_code=500, detail=str(e))        



@router.put("/update-user")
async def update_user(
    request: UserUpdateRequest,  # El modelo con los datos a actualizar
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        # Decodificar el token para obtener el correo del usuario autenticado
        token = credentials.credentials
        payload = decode_access_token(token)
        authenticated_email = payload.get("sub")

        if not authenticated_email:
            raise HTTPException(status_code=400, detail="Token inválido")

        # Buscar al usuario en la base de datos por correo
        user = db.query(User).filter(User.correo == authenticated_email).first()

        if not user:
            raise HTTPException(
                status_code=404, detail="Usuario no encontrado")

        # Actualizar los campos del usuario con la información del request
        if request.name:
            user.nombre = request.name
        if request.last_name:
            user.apellido = request.last_name
        if request.email:
            user.correo = request.email
        if request.provider:
            user.proveedor = request.provider

        db.commit()

        return {
            "status": "success",
            "message": "Datos de usuario actualizados correctamente",
            "data": {
                "name": user.nombre,  
                "last_name": user.apellido,  
                "email": user.correo, 
                "provider": user.proveedor,  
            },
        }

    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))

# Roadmaps
@router.post("/preview-cost-process-file")
async def preview_cost_process_file(
    request: ProcessFileRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
    ):
    """
    Obtener un costo estimado de cuanto cuesta procesar cierto archivo
    """
    # Calcular costo de creditos
    full_prompt = (
        f"Eres un experto en la extracción de los 3 temas principales de los cuales se pueden generar una ruta de "
        f"aprendizaje de un archivo. El archivo tiene el siguiente nombre {request.fileName} y este es el contenido: {request.fileBase64}. Quiero que el formato de la respuesta sea una"
        f"lista con únicamente los 3 temas principales y nada más, es decir: [\"tema1\", \"tema2\", \"tema3\"] "
    )

    tokens = count_tokens_gemini(full_prompt)

    if tokens >= 1000000:
        raise HTTPException(
            status_code=406, detail="Se superó la cantidad máxima de tokens")

    credits_cost = price_roadmap(tokens)

    # Decodificar el token para obtener el correo del usuario autenticado
    auth_token = credentials.credentials
    payload = decode_access_token(auth_token)
    authenticated_email = payload.get("sub")

    if not authenticated_email:
        raise HTTPException(status_code=400, detail="Token de Ingreso inválido")

    # Buscar al usuario en la base de datos por correo
    user = db.query(User).filter(User.correo == authenticated_email).first()

    if not user:
        raise HTTPException(
            status_code=404, detail="Usuario no encontrado")

    # Actualizar la cantidad de creditos
    user_credits = user.creditos

    response = json.dumps({
        "user_credits": user_credits,
        "credits_cost": credits_cost
    })

    return response

    


@router.post("/process-file")
async def process_file(
    request: ProcessFileRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
    ):
    """
    Procesar un archivo y obtener las roadmaps
    """
    # print("Se van a generar los 3 temas")
    full_prompt = (
        f"Eres un experto en la extracción de los 3 temas principales de los cuales se pueden generar una ruta de "
        f"aprendizaje de un archivo. El archivo tiene el siguiente nombre {request.fileName} y este es el contenido: {request.fileBase64}. Quiero que el formato de la respuesta sea una"
        f"lista con únicamente los 3 temas principales y nada más, es decir: [\"tema1\", \"tema2\", \"tema3\"] "
    )

    themes, tokens = ask_gemini(full_prompt)

    themes = json.loads(themes.replace("\n", ""))
    cost = price_roadmap(int(tokens))

    # Decodificar el token para obtener el correo del usuario autenticado
    auth_token = credentials.credentials
    payload = decode_access_token(auth_token)
    authenticated_email = payload.get("sub")

    if not authenticated_email:
        raise HTTPException(status_code=400, detail="Token de Ingreso inválido")

    # Buscar al usuario en la base de datos por correo
    user = db.query(User).filter(User.correo == authenticated_email).first()

    if not user:
        raise HTTPException(
            status_code=404, detail="Usuario no encontrado")

    # Actualizar la cantidad de creditos
    if user.creditos < cost:
        raise HTTPException(
            status_code=402, detail="Creditos insuficientes para la acción")

    user.creditos -= cost
    db.commit()

    # Retornar la respuesta con los temas del documento y el costo en creditos
    # print(themes, "tipo:", type(themes))

    response = json.dumps({
    "themes": themes,
    "cost": cost
    })
    
    return response


@router.post("/generate-roadmap")
async def generate_roadmap(request: TopicRequest):
    """
    Generar una roadmap a partir de los temas
    """
    # print("Se va a generar la ruta de aprendizaje")
    full_prompt = (
        f"Eres un experto en la creación de rutas de aprendizaje basadas en un tema específico. El tema principal es {request.topic}. "
        f"Quiero que el formato de la respuesta sea un diccionario anidado donde la clave sea el tema principal y los valores sean diccionarios de subtemas, "
        f"cada uno con su propia lista de subtemas adicionales. "
        f"Por ejemplo: '{{\"Subtema 1\": [\"Sub-subtema 1.1\", \"Sub-subtema 1.2\"], \"Subtema 2\": [\"Sub-subtema 2.1\", \"Sub-subtema 2.2\"]}}' con las comillas tal cual como te las di. "
        f"No me des información extra, solo quiero el diccionario anidado con los subtemas y sus sub-subtemas en orden de relevancia. MÁXIMO 6 SubtemaS, MÁXIMO 3 Sub-subtemas y MÍNIMO 1 Sub-subtema ."
    )
    response, tokens = ask_gemini(full_prompt)
    print("DIOOOO", response)
    parse_resposne = response.replace("json", "").replace("```", "")
    # print("parseado:", parse_resposne)
    # print("Tokens usados para este prompt:", tokens)
    return parse_resposne


@router.post("/save-roadmap-image")
async def save_roadmap_image(
    request: RoadmapImageRequest,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    token = credentials.credentials 

    try:
        payload = decode_access_token(token)
        email = payload.get("sub")

        if not email:
            raise HTTPException(status_code=400, detail="Token inválido")

        user = db.query(User).filter_by(correo=email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        id_usuario_creador = user.id_usuario

        # Verificar si el roadmap ya existe
        existing_roadmap = db.query(Roadmap).filter_by(
            nombre=request.topic, id_usuario_creador=id_usuario_creador
        ).first()

        if existing_roadmap:
            # Si ya existe, solo actualizamos la imagen
            existing_roadmap.image = request.image_base64
            db.commit()
            return {"message": "Imagen actualizada correctamente"}

        # Si no existe, lo creamos con la imagen
        new_roadmap = Roadmap(
            nombre=request.topic,
            id_usuario_creador=id_usuario_creador,
            prompt=request.roadmap_data,  # Guardamos la información generada
            image_base64=request.image_base64  # Guardamos la imagen en base64
        )
        db.add(new_roadmap)
        db.commit()
        db.refresh(new_roadmap)

        return {"message": "Roadmap y imagen guardados correctamente"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


@router.post("/related-topics")
async def related_topics(request: TopicRequest):
    """
    Obtener temas relacionados a un tema principal
    """
    print("Se van a obtener temas relacionados")
    full_prompt = (
        f"Eres un experto en la generación de temas relacionados a un tema principal. El tema principal es {request.topic}. Quiero que el formato de la respuesta sea una"
        f"lista con únicamente MÁXIMO 6 temas relacionados y NADA MÁS, es decir: [\"tema1\", \"tema2\", \"tema3\"] "
    )
    response, tokens = ask_gemini(full_prompt)
    parse_resposne = response.replace("json", "").replace("```", "")
    print("parseado:", parse_resposne)
    return parse_resposne

