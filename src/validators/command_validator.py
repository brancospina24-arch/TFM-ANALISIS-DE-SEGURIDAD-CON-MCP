import re


PATRONES_PELIGROSOS = [
    r";",
    r"&&",
    r"\|\|",
    r"\|",
    r"`",
    r"\$\(",
    r">",
    r"<",
    r"rm\s+-rf",
    r"cat\s+/etc/passwd",
    r"sudo",
    r"wget",
    r"curl"
]


def validar_comando_seguro(entrada: str) -> bool:
    texto = entrada.lower()

    for patron in PATRONES_PELIGROSOS:
        if re.search(patron, texto):
            raise ValueError("Command Injection bloqueado: patrón peligroso detectado.")

    return True
