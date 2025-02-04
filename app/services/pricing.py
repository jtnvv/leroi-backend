
def calculate_price(amount: int):
    """
    Función usada para calcular el precio según la cantidad de creditos.
    :param amount: Cantidad de creditos que se comprarán.
    :return: Precio en dolares.
    """
    if 1 <= amount <= 250:
        return round(amount*0.005)
    elif 250 <= amount <= 750:
        return round(amount*0.00495)
    elif 750 <= amount <= 1500:
        return round(amount*0.0049)
