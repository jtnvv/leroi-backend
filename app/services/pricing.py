import os
import mercadopago
from mercadopago.config import RequestOptions

##SMP_ACCESS_TOKEN = os.getenv("MP_ACCESS_TOKEN")
##sdk = mercadopago.SDK(MP_ACCESS_TOKEN)


def calculate_price(amount: int):
    """
    Función usada para calcular el precio según la cantidad de creditos.
    :param amount: Cantidad de creditos que se comprarán.
    :return: Precio en dolares.
    """
    if 1 <= amount <= 250:
        return round(amount*0.5)
    elif 250 <= amount <= 750:
        return round(amount*0.495)
    elif 750 <= amount <= 1500:
        return round(amount*0.49)


async def initiate_payment(request):
    """
    Inicia un pago usando la API de MercadoPago.
    :param request: Objeto PaymentRequest con la información del pago.
    :return: URL para completar el pago.
    """
    try:
        u_price = calculate_price(request.amount)
        # Datos del pago
        preference_data = {
            "items": [
                {
                    "title": f"Compra de {request.amount} creditos - Leroi",
                    "quantity": 1,
                    "unit_price": u_price
                }
            ]
        }

        # Crear el pago
        preference_response = sdk.preference().create(preference_data)
        preference = preference_response["response"]
        # Retornar la URL de aprobación para redirigir al usuario
        return preference.get("init_point")
    except Exception as e:
        raise RuntimeError(f"Error iniciando el pago: {str(e)}")
