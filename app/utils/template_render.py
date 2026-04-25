from jinja2 import Template


def render_template(template_str: str, data: dict) -> str:
    """
    Renderiza una plantilla Jinja2 a partir de un string y un diccionario de datos.

    Se utiliza para generar contenido dinámico, por ejemplo:
    - Emails HTML
    - Mensajes personalizados
    - Plantillas de texto plano

    :param template_str: Plantilla en formato string (Jinja2)
    :param data: Diccionario con los valores a interpolar en la plantilla
    :return: String con la plantilla renderizada
    :raises ValueError: Si la plantilla está vacía
    """
    # Validación básica para evitar renderizar plantillas vacías
    if not template_str:
        raise ValueError("Template string cannot be empty")

    # Renderiza la plantilla utilizando Jinja2
    template = Template(template_str).render(**data)
    return template
