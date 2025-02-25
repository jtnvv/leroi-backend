
def calculate_price(amount: int):
    """
    Función usada para calcular el precio según la cantidad de creditos.
    :param amount: Cantidad de creditos que se comprarán.
    :return: Precio en dolares.
    """
    if 1 <= amount <= 250:
        return 1.0
    elif 250 < amount <= 750:
        return 2.75
    elif 750 < amount <= 1500:
        return 5.0
