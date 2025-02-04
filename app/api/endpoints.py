import jwt
import os
from fastapi import APIRouter, Depends, HTTPException, Request
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
    PaymentRequest,
    ProcessFileRequest,
    TopicRequest
)
from app.services.login import create_access_token, decode_access_token, verify_password
from app.services.pricing import calculate_price
from app.services.ai import ask_gemini
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from datetime import timedelta
import mercadopago

router = APIRouter()
security = HTTPBearer()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
FRONTEND_URL = os.getenv("FRONTEND_URL")
MP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")

TEST_PORT = os.getenv("TEST_PORT")

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
        raise HTTPException(
            status_code=401, detail="Ya has iniciado sesión con Google")
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


@router.post("/create-payment")
async def create_payment(request: PaymentRequest):
    """
    Inicia un pago usando la API de MercadoPago.

    Args:
        request (PaymentRequest): Datos del pago enviados desde el frontend.

    Returns:
        dict: URL para redirigir al usuario.
    """
    try:
        u_price = calculate_price(request.amount)
        # Datos del pago

        preference_data = {
            "items": [
                {
                    "id": 1,
                    "title": f"Compra de {request.amount} creditos - Leroi",
                    "quantity": 1,
                    "unit_price": u_price,
                    "currency_id": "USD",
                }
            ],
            "back_urls": {
                # "success": "localhost:5173/homepage",
                # "failure": "localhost:5173/order-failed",
                # "pending": "localhost:5173/pending"
                "success": "localhost:5173",
                "failure": "localhost:5173",
                "pending": "localhost:5173"
            },
            # "auto_return": "approved",
            "notification_url": TEST_PORT + "/mercadopago/paymentNotification"
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
async def payment_listener(request: Request):
    """
    Endpoint para recibir notificaciones de pago de MercadoPago.

    Args:
        request (PaymentRequest): Datos enviados desde MercadoPago.

    Returns:
        status: 200 (En caso de que todo esté bien)
        status: diferente de 200 (En caso de que exista algún error)

    """
    try:
        # Obtenemos el cuerpo de la solicitud
        body = await request.json()
        # print("Notificación recibida:", body)

        # Verificamos si la notificación es de pago o de merchant_order
        # 'topic' en algunas, 'type' en otras
        topic = body.get("topic") or body.get("type")
        resource = body.get("resource")

        # Si es de tipo 'merchant_order', ignoramos.
        if topic == "merchant_order":
            # print(f"Notificación de 'merchant_order': {resource}")
            # Respondemos con 200 OK para evitar reintentos
            return {"status": "received"}

        # Si es de tipo 'payment', obtenemos el ID
        payment_id = None
        if topic == "payment":
            payment_id = body.get("data", {}).get("id")
        elif "id" in body:  # Compatibilidad con otros formatos
            payment_id = body["id"]

        if not payment_id:
            # print("Error: ID de pago no encontrado en la notificación.")
            return {"status": "error", "message": "ID de pago no encontrado"}, 400

        # Intentamos obtener los detalles del pago
        payment = sdk.payment().get(payment_id).get("response")

        if not payment:
            print(f"Error: No se pudo obtener información del pago {
                  payment_id}")
            return {"status": "error", "message": "Pago no encontrado"}, 400

        # Verificamos si el pago fue aprobado
        if payment.get("status") == "approved":
            print(f"Pago aprobado: ID={payment_id}")

            # Lógica para procesamiento de pago

        return {"status": "success", "message": "Notificación procesada correctamente"}

    except Exception as e:
        print(f"Error procesando el webhook: {str(e)}")
        # Asegurar respuesta en todos los casos
        return {"status": "error", "message": str(e)}, 500
# Roadmaps


@router.post("/process-file")
async def process_file(request: ProcessFileRequest):
    """
    Procesar un archivo y obtener las roadmaps
    """
    print("Se van a generar los 3 temas")
    full_prompt = (
        f"Eres un experto en la extracción de los 3 temas principales de los cuales se pueden generar una ruta de "
        f"aprendizaje de un archivo. El archivo tiene el siguiente nombre {request.fileName} y este es el contenido: {
            request.fileBase64}. Quiero que el formato de la respuesta sea una"
        f"lista con únicamente los 3 temas principales y nada más, es decir: [\"tema1\", \"tema2\", \"tema3\"] "
    )
    response = ask_gemini(full_prompt)
    print(response, "tipo:", type(response))
    return response


@router.post("/generate-roadmap")
async def generate_roadmap(request: TopicRequest):
    """
    Generar una roadmap a partir de los temas
    """
    print("Se va a generar la ruta de aprendizaje")
    full_prompt = (
        f"Eres un experto en la creación de rutas de aprendizaje basadas en un tema específico. El tema principal es {
            request.topic}. "
        f"Quiero que el formato de la respuesta sea un diccionario anidado donde la clave sea el tema principal y los valores sean diccionarios de subtemas, "
        f"cada uno con su propia lista de subtemas adicionales. "
        f"Por ejemplo: '{{\"Subtema 1\": [\"Sub-subtema 1.1\", \"Sub-subtema 1.2\"], \"Subtema 2\": [\"Sub-subtema 2.1\", \"Sub-subtema 2.2\"]}}' con las comillas tal cual como te las di. "
        f"No me des información extra, solo quiero el diccionario anidado con los subtemas y sus sub-subtemas en orden de relevancia. MÁXIMO 6 SubtemaS, MÁXIMO 3 Sub-subtemas y MÍNIMO 1 Sub-subtema ."
    )
    response = ask_gemini(full_prompt)
    parse_resposne = response.replace("json", "").replace("```", "")
    print("parseado:", parse_resposne)
    return parse_resposne
