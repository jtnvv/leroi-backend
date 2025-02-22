def price_roadmap(tokens):
    """
    Función usada para calcular el precio de un roadmap.
    :param tokens: Cantidad de tokens consumidos.
    :return: Cantidad de creditos que costará realizar el roadmap.
    """
    return round(tokens*0.001) + 1