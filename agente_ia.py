import asyncio
import os
import re
from dotenv import load_dotenv
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
 
load_dotenv()
 
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
 
RUTAS_PERMITIDAS = [
    "documentos/",
    "safe_files/",
    "logs/"
]
 
PATRONES_COMMAND_INJECTION = [
    r";",
    r"\|\|",
    r"\|",
    r"&&",
    r"`",
    r"\$\(.*\)",
    r"rm\s+-rf",
    r"wget",
    r"curl",
    r"nc",
    r"bash",
    r"cat\s+/etc/passwd"
]
 
 
def clasificar_intencion(solicitud: str) -> dict:
    texto = solicitud.strip()
 
 # 1. Rutas permitidas → BAJO
    for ruta in RUTAS_PERMITIDAS:
        if texto.startswith(ruta) or ruta in texto:
            return {
                "herramienta": "validar_path_seguro",
                "argumentos": {
                    "ruta": texto,
                    "riesgo": "BAJO",
                    "descripcion": f"La ruta '{texto}' está dentro de las permitidas."
                }
            }

    # 2. Path Traversal → ALTO
    if "../" in texto or "..\\" in texto or "/etc/passwd" in texto or "Windows/System32" in texto:
        return {
            "herramienta": "validar_path_traversal",
            "argumentos": {
                "ruta": texto,
                "riesgo": "ALTO",
                "descripcion": "Se detectó intento de acceso a rutas no autorizadas."
            }
        }

    # 3. Command Injection → ALTO
    if any(re.search(patron, texto, re.IGNORECASE) for patron in PATRONES_COMMAND_INJECTION):
        return {
            "herramienta": "validar_command_injection",
            "argumentos": {
                "entrada": texto,
                "riesgo": "ALTO",
                "descripcion": "Se detectó posible intento de command injection."
            }
        }

    # 4. SSRF → ALTO
    if "169.254.169.254" in texto or "localhost" in texto.lower() or "127.0.0.1" in texto or "ssrf" in texto.lower():
        url_detectada = extraer_url(texto)
        return {
            "herramienta": "validar_ssrf",
            "argumentos": {
                "url": url_detectada if url_detectada else texto,
                "riesgo": "ALTO",
                "descripcion": "Se detectó posible intento de SSRF."
            }
        }

    # 5. URL normal → ALTO si es HTTP, BAJO si es HTTPS
    if "http://" in texto or "https://" in texto:
        url_detectada = extraer_url(texto)
        riesgo = "ALTO" if "http://" in texto else "BAJO"
        return {
            "herramienta": "analizar_url",
            "argumentos": {
                "url": url_detectada if url_detectada else texto,
                "riesgo": riesgo,
                "descripcion": f"La URL utiliza {'HTTP inseguro' if riesgo=='ALTO' else 'HTTPS seguro'}."
            }
        }

    # 6. Default → sospechosa
    return {
        "herramienta": "analizar_url",
        "argumentos": {
            "url": texto,
            "riesgo": "ALTO",
            "descripcion": "Entrada no reconocida, tratada como sospechosa."
        }
    } 
 
def extraer_url(texto: str) -> str:
    coincidencia = re.search(r"https?://[^\s]+", texto)
    return coincidencia.group(0) if coincidencia else ""
 
 
async def ejecutar_herramienta_mcp(herramienta: str, argumentos: dict):
    server_params = StdioServerParameters(
        command="/home/mcp/mcp-threat-detection/venv/bin/python",
        args=["-m", "src.main"],
        cwd="/home/mcp/mcp-threat-detection"
    )
 
    try:
        async with stdio_client(server_params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
 
                resultado = await asyncio.wait_for(
                    session.call_tool(herramienta, argumentos),
                    timeout=10
                )
 
                return resultado.content
 
    except Exception as error:
        return [
            {
                "type": "text",
                "text": f"Error al ejecutar herramienta MCP: {error}"
            }
        ]
 
 
def explicar_resultado(solicitud: str, resultado_mcp) -> str:
    prompt = f"""
Actúa como analista SOC bajo el enfoque Zero Trust.
 
Solicitud del analista:
{solicitud}
 
Resultado técnico entregado por el servidor MCP:
{resultado_mcp}
 
Explica de forma breve y clara:
- Qué se detectó.
- Nivel de riesgo.
- Por qué cumple con el enfoque Zero Trust.
- Acción recomendada.
 
Importante:
No inventes un nivel de riesgo diferente al entregado por el servidor MCP.
El riesgo oficial es el que aparece en el resultado MCP.
"""
 
    try:
        response = client.responses.create(
            model="gpt-4.1-mini",
            input=prompt
        )
        return response.output_text
 
    except Exception as error:
        return f"No fue posible generar explicación con IA. Detalle: {error}"
 
 
async def main():
    print("\nAGENTE SOC CON IA + MCP (Zero Trust)")
    print("Escribe 'salir' para finalizar.\n")
 
    while True:
        solicitud = input("Solicitud del analista SOC: ")
 
        if solicitud.lower().strip() == "salir":
            break
 
        decision = clasificar_intencion(solicitud)
        herramienta = decision.get("herramienta")
        argumentos = decision.get("argumentos", {})
 
        print("\nHerramienta seleccionada por IA:")
        print(herramienta)
 
        print("\nArgumentos enviados al servidor MCP:")
        print(argumentos)
 
        resultado_mcp = await ejecutar_herramienta_mcp(
            herramienta,
            argumentos
        )
 
        print("\nResultado MCP:")
        print(resultado_mcp)
 
        explicacion = explicar_resultado(
            solicitud,
            resultado_mcp
        )
 
        print("\nExplicación IA:")
        print(explicacion)
        print("\n" + "-" * 60 + "\n")
 
 
if __name__ == "__main__":
    asyncio.run(main())
