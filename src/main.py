from src.validators.ssrf_validator import validar_url_segura
from src.validators.path_validator import validar_ruta_segura
from src.validators.command_validator import validar_comando_seguro
from mcp.server.fastmcp import FastMCP
from urllib.parse import urlparse
from datetime import datetime
import json
import os

mcp = FastMCP("ThreatDetectionMCP")

LOG_FILE = "logs/security_events.json"


def registrar_evento(tipo: str, riesgo: str, descripcion: str, entrada: str) -> dict:
    """
    Registra eventos de seguridad en formato JSON.
    """

    os.makedirs("logs", exist_ok=True)

    evento = {
        "fecha": datetime.now().isoformat(),
        "tipo": tipo,
        "riesgo": riesgo,
        "descripcion": descripcion,
        "entrada": entrada
    }

    with open(LOG_FILE, "a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(evento, ensure_ascii=False) + "\n")

    return evento


@mcp.tool()
def ping() -> str:
    """
    Verifica que el servidor MCP está funcionando.
    """
    return "Servidor MCP funcionando correctamente"


@mcp.tool()
def analizar_url(url: str) -> dict:
    """
    Analiza una URL para identificar posibles riesgos de phishing,
    uso inseguro de HTTP o dominios sospechosos.
    """

    parsed = urlparse(url)
    dominio = parsed.hostname or ""

    dominios_sospechosos = [
        "verify-account.com",
        "login-seguro.net",
        "malicious-site.com",
        "secure-login-update.com"
    ]

    if parsed.scheme != "https":
        return registrar_evento(
            tipo="URL sospechosa",
            riesgo="ALTO",
            descripcion="La URL no utiliza HTTPS.",
            entrada=url
        )

    if dominio in dominios_sospechosos:
        return registrar_evento(
            tipo="Dominio sospechoso",
            riesgo="ALTO",
            descripcion="Dominio asociado a posible phishing.",
            entrada=url
        )

    return registrar_evento(
        tipo="URL validada",
        riesgo="BAJO",
        descripcion="La URL supera las validaciones básicas.",
        entrada=url
    )


@mcp.tool()
def analizar_correo(remitente: str, asunto: str, cuerpo: str) -> dict:
    """
    Analiza un correo electrónico para identificar señales básicas de phishing.
    """

    texto = f"{remitente} {asunto} {cuerpo}".lower()

    palabras_riesgo = [
        "urgente",
        "verificar cuenta",
        "contraseña",
        "bloqueo",
        "actualizar datos",
        "premio",
        "pago pendiente",
        "credenciales"
    ]

    indicadores = []

    for palabra in palabras_riesgo:
        if palabra in texto:
            indicadores.append(palabra)

    if len(indicadores) >= 3:
        riesgo = "ALTO"
        descripcion = "Correo con múltiples indicadores asociados a phishing."
    elif len(indicadores) >= 1:
        riesgo = "MEDIO"
        descripcion = "Correo con algunos elementos sospechosos."
    else:
        riesgo = "BAJO"
        descripcion = "Correo sin indicadores evidentes de phishing."

    entrada = {
        "remitente": remitente,
        "asunto": asunto,
        "indicadores": indicadores
    }

    return registrar_evento(
        tipo="Análisis de correo",
        riesgo=riesgo,
        descripcion=descripcion,
        entrada=json.dumps(entrada, ensure_ascii=False)
    )


@mcp.tool()
def consultar_ioc(indicador: str) -> dict:
    """
    Consulta un indicador de compromiso en una base simulada.
    """

    base_ioc = {
        "verify-account.com": "Dominio asociado a phishing.",
        "malicious-site.com": "Dominio malicioso simulado.",
        "192.168.10.55": "IP relacionada con actividad sospechosa.",
        "secure-login-update.com": "Dominio usado para robo de credenciales."
    }

    if indicador in base_ioc:
        return registrar_evento(
            tipo="IOC detectado",
            riesgo="ALTO",
            descripcion=base_ioc[indicador],
            entrada=indicador
        )

    return registrar_evento(
        tipo="IOC no detectado",
        riesgo="BAJO",
        descripcion="No se encontró coincidencia en la base IOC simulada.",
        entrada=indicador
    )


@mcp.tool()
def generar_alerta(tipo_evento: str, riesgo: str, descripcion: str) -> dict:
    """
    Genera una alerta de seguridad simulada.
    """

    alerta = {
        "id_alerta": f"ALERTA-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "fecha": datetime.now().isoformat(),
        "tipo_evento": tipo_evento,
        "riesgo": riesgo,
        "descripcion": descripcion,
        "estado": "Pendiente de revisión por analista SOC"
    }

    os.makedirs("logs", exist_ok=True)

    with open("logs/alerts.json", "a", encoding="utf-8") as archivo:
        archivo.write(json.dumps(alerta, ensure_ascii=False) + "\n")

    return alerta

@mcp.tool()
def validar_ssrf(url: str) -> dict:
    try:
        validar_url_segura(url)

        return registrar_evento(
            tipo="Validación SSRF",
            riesgo="BAJO",
            descripcion="URL permitida. No se identificó riesgo SSRF.",
            entrada=url
        )

    except Exception as error:
        return registrar_evento(
            tipo="SSRF bloqueado",
            riesgo="CRÍTICO",
            descripcion=str(error),
            entrada=url
        )


@mcp.tool()
def validar_path_traversal(ruta: str) -> dict:
    try:
        ruta_segura = validar_ruta_segura(ruta)

        return registrar_evento(
            tipo="Validación Path Traversal",
            riesgo="BAJO",
            descripcion=f"Ruta permitida: {ruta_segura}",
            entrada=ruta
        )

    except Exception as error:
        return registrar_evento(
            tipo="Path Traversal bloqueado",
            riesgo="CRÍTICO",
            descripcion=str(error),
            entrada=ruta
        )


@mcp.tool()
def validar_command_injection(entrada: str) -> dict:
    try:
        validar_comando_seguro(entrada)

        return registrar_evento(
            tipo="Validación Command Injection",
            riesgo="BAJO",
            descripcion="Entrada permitida. No se detectaron patrones peligrosos.",
            entrada=entrada
        )

    except Exception as error:
        return registrar_evento(
            tipo="Command Injection bloqueado",
            riesgo="CRÍTICO",
            descripcion=str(error),
            entrada=entrada
        )







if __name__ == "__main__":
    mcp.run()


