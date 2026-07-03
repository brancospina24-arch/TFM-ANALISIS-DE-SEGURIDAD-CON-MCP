import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
 
 
async def main():
    solicitud = input("Ingrese la solicitud del analista SOC: ").lower()
 
    server_params = StdioServerParameters(
        command="/home/mcp/mcp-threat-detection/venv/bin/python",
        args=["-m", "src.main"],
        cwd="/home/mcp/mcp-threat-detection"
    )
 
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
 
            if "ssrf" in solicitud or "169.254" in solicitud:
                result = await session.call_tool(
                    "validar_ssrf",
                    {"url": "http://169.254.169.254/latest/meta-data/"}
                )
 
            elif "path" in solicitud or "../" in solicitud:
                result = await session.call_tool(
                    "validar_path_traversal",
                    {"ruta": "../../etc/passwd"}
                )
 
            elif "command" in solicitud or "rm -rf" in solicitud:
                result = await session.call_tool(
                    "validar_command_injection",
                    {"entrada": "; rm -rf /"}
                )
 
            elif "url" in solicitud or "http" in solicitud:
                result = await session.call_tool(
                    "analizar_url",
                    {"url": "https://verify-account.com/login"}
                )
 
            else:
                result = "No se identificó una herramienta adecuada."
 
            print("\nResultado del análisis:")
            print(result.content if hasattr(result, "content") else result)
 
 
if __name__ == "__main__":
    asyncio.run(main())
