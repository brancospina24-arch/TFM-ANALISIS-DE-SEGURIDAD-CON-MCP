import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
 
 
async def main():
    server_params = StdioServerParameters(
        command="/home/mcp/mcp-threat-detection/venv/bin/python",
        args=["-m", "src.main"],
        cwd="/home/mcp/mcp-threat-detection"
    )
 
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
 
            tools = await session.list_tools()
            print("\nHERRAMIENTAS MCP DISPONIBLES:")
            for tool in tools.tools:
                print("-", tool.name)
 
            print("\nPRUEBA DESDE CLIENTE MCP - SSRF")
            result = await session.call_tool(
                "validar_ssrf",
                {"url": "http://169.254.169.254/latest/meta-data/"}
            )
            print(result.content)
 
            print("\nPRUEBA DESDE CLIENTE MCP - PATH TRAVERSAL")
            result = await session.call_tool(
                "validar_path_traversal",
                {"ruta": "../../etc/passwd"}
            )
            print(result.content)
 
            print("\nPRUEBA DESDE CLIENTE MCP - COMMAND INJECTION")
            result = await session.call_tool(
                "validar_command_injection",
                {"entrada": "; rm -rf /"}
            )
            print(result.content)
 
 
if __name__ == "__main__":
    asyncio.run(main())
