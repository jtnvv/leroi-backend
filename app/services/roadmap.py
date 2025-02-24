def price_roadmap(tokens):
    """
    Función usada para calcular el precio de un roadmap.
    :param tokens: Cantidad de tokens consumidos.
    :return: Cantidad de creditos que costará realizar el roadmap.
    """
    return (int(tokens*0.0001) + 1)
