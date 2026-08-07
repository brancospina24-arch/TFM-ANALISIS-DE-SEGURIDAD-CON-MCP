# 1. Librerías y configuración
import asyncio
import os
import re
import requests
import urllib3
from dotenv import load_dotenv
from openai import OpenAI
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

RUTAS_PERMITIDAS = ["documentos/", "safe_files/", "logs/"]
PATRONES_COMMAND_INJECTION = [
    r";", r"\|\|", r"\|", r"&&", r"`", r"\$\(.*\)",
    r"rm\s+-rf", r"wget", r"curl", r"nc", r"bash", r"cat\s+/etc/passwd"
]

# 2. Conexión con Wazuh Manager
def conectar_wazuh(usuario="admin", clave="NuevaClave123", host="https://127.0.0.1", port=55000):
    try:
        auth_url = f"{host}:{port}/security/user/authenticate"
        auth = requests.post(auth_url, auth=(usuario, clave), verify=False)
        auth.raise_for_status()
        token = auth.json()["data"]["token"]
        headers = {"Authorization": f"Bearer {token}"}
        agents_url = f"{host}:{port}/agents"
        resp = requests.get(agents_url, headers=headers, verify=False)
        resp.raise_for_status()
        return resp.json()["data"]["affected_items"]
    except Exception as e:
        print("Error al conectar con Wazuh:", e)
        return None

# 3. Fallback de eventos: Manager → Indexer → Logs locales
def obtener_eventos_wazuh(usuario="admin", clave="NuevaClave123", host="https://127.0.0.1", port=55000, limit=5):
    try:
        auth_url = f"{host}:{port}/security/user/authenticate"
        auth = requests.post(auth_url, auth=(usuario, clave), verify=False)
        auth.raise_for_status()
        token = auth.json()["data"]["token"]
        headers = {"Authorization": f"Bearer {token}"}

        for url, method, payload in [
            (f"{host}:{port}/alerts?limit={limit}&sort=desc", "GET", None),
            (f"{host}:{port}/events", "POST", {"query": "*", "limit": limit, "sort": {"field": "timestamp", "order": "desc"}}),
            (f"{host}:{port}/security/events?limit={limit}&sort=desc", "GET", None)
        ]:
            try:
                if method == "GET":
                    resp = requests.get(url, headers=headers, verify=False)
                else:
                    resp = requests.post(url, headers=headers, json=payload, verify=False)
                resp.raise_for_status()
                return resp.json()["data"]["affected_items"]
            except:
                continue
        return None
    except Exception as e:
        print("Error al obtener eventos de Wazuh:", e)
        return None

def obtener_eventos_indexer(usuario="admin", clave="NuevaClave123", host="https://127.0.0.1", port=9200, limit=5):
    try:
        url = f"{host}:{port}/wazuh-alerts-*/_search"
        payload = {
            "size": limit,
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {"match_all": {}}
        }
        resp = requests.get(url, auth=(usuario, clave), json=payload, verify=False)
        resp.raise_for_status()
        hits = resp.json()["hits"]["hits"]
        return [hit["_source"] for hit in hits]
    except Exception as e:
        print("Error al obtener eventos del Indexer:", e)
        return None

def obtener_eventos_local(limit=5):
    try:
        eventos = []
        with open("/var/ossec/logs/alerts/alerts.json", "r") as f:
            for linea in f.readlines()[-limit:]:
                eventos.append(linea.strip())
        return eventos
    except Exception as e:
        print("Error al leer eventos locales:", e)
        return None

# 4. Clasificación de intenciones
def clasificar_intencion(solicitud: str) -> dict:
    texto = solicitud.strip()
    for ruta in RUTAS_PERMITIDAS:
        if texto.startswith(ruta) or ruta in texto:
            return {"herramienta": "validar_path_seguro",
                    "argumentos": {"ruta": texto, "riesgo": "BAJO",
                                   "descripcion": f"La ruta '{texto}' está dentro de las permitidas."}}
    if "../" in texto or "..\\" in texto or "/etc/passwd" in texto or "Windows/System32" in texto:
        return {"herramienta": "validar_path_traversal",
                "argumentos": {"ruta": texto, "riesgo": "ALTO",
                               "descripcion": "Se detectó intento de acceso a rutas no autorizadas."}}
    if any(re.search(patron, texto, re.IGNORECASE) for patron in PATRONES_COMMAND_INJECTION):
        return {"herramienta": "validar_command_injection",
                "argumentos": {"entrada": texto, "riesgo": "ALTO",
                               "descripcion": "Se detectó posible intento de command injection."}}
    if "169.254.169.254" in texto or "localhost" in texto.lower() or "127.0.0.1" in texto or "ssrf" in texto.lower():
        return {"herramienta": "validar_ssrf",
                "argumentos": {"url": extraer_url(texto) or texto, "riesgo": "ALTO",
                               "descripcion": "Se detectó posible intento de SSRF."}}
    if "http://" in texto or "https://" in texto:
        riesgo = "ALTO" if "http://" in texto else "BAJO"
        return {"herramienta": "analizar_url",
                "argumentos": {"url": extraer_url(texto) or texto, "riesgo": riesgo,
                               "descripcion": f"La URL utiliza {'HTTP inseguro' if riesgo=='ALTO' else 'HTTPS seguro'}."}}
    return {"herramienta": "analizar_url",
            "argumentos": {"url": texto, "riesgo": "ALTO",
                           "descripcion": "Entrada no reconocida, tratada como sospechosa."}}

def extraer_url(texto: str) -> str:
    coincidencia = re.search(r"https?://[^\s]+", texto)
    return coincidencia.group(0) if coincidencia else ""

# 5. Ejecución de herramientas MCP
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
                resultado = await asyncio.wait_for(session.call_tool(herramienta, argumentos), timeout=10)
                return resultado.content
    except Exception as error:
        return [{"type": "text", "text": f"Error al ejecutar herramienta MCP: {error}"}]

# 6. Explicación Zero Trust con IA
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
"""
    try:
        response = client.responses.create(model="gpt-4.1-mini", input=prompt)
        return response.output_text
    except Exception as error:
        return f"No fue posible generar explicación con IA. Detalle: {error}"

# 7. Main
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

        print("\n[1] Herramienta seleccionada por IA:")
        print(herramienta)
        print("\n[2] Argumentos enviados al servidor MCP:")
        print(argumentos)

        resultado_mcp = await ejecutar_herramienta_mcp(herramienta, argumentos)
        print("\n[3] Resultado MCP:")
        print(resultado_mcp)

        explicacion = explicar_resultado(solicitud, resultado_mcp)
        print("\n[4] Explicación IA:")
        print(explicacion)

        # -------------------------------
        # Validar conexión con Wazuh
        # -------------------------------
        agentes = conectar_wazuh()
        if agentes:
            print("\n[5] [Wazuh] Conexión OK. Agentes activos detectados:")
            for ag in agentes:
                print(f"- {ag['name']} ({ag['os']['name']} {ag['os']['version']}) → {ag['status']}")
        else:
            print("\n[5] [Wazuh] No fue posible conectar con el Manager.")

        # Consultar eventos recientes con fallback
        eventos = obtener_eventos_wazuh(limit=5)
        if not eventos:
            eventos = obtener_eventos_indexer(limit=5)
        if not eventos:
            eventos = obtener_eventos_local(limit=5)

        if eventos:
            print("\n[6] [Wazuh] Últimos eventos detectados:")
            for ev in eventos:
                desc = ev['rule']['description'] if isinstance(ev, dict) and 'rule' in ev else str(ev)
                nivel = ev['rule']['level'] if isinstance(ev, dict) and 'rule' in ev else "N/A"
                ts = ev['timestamp'] if isinstance(ev, dict) and 'timestamp' in ev else "Sin timestamp"
                print(f"- {desc} (nivel {nivel}) → {ts}")
        else:
            print("\n[6] [Wazuh] No se pudieron obtener eventos recientes.")

        print("\n" + "-" * 60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())
