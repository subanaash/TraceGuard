"""Starts the MCP server over stdio, lists its tools and calls two of them. Needs the API running."""
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    params = StdioServerParameters(command=sys.executable, args=["server.py"])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = await s.list_tools()
            print("tools:", [t.name for t in tools.tools])
            r = await s.call_tool("triage_identities", {})
            print("triage ->", r.content[0].text[:300])
            r = await s.call_tool("apply_containment", {"edges": [{"source": "a", "target": "b", "type": "CONNECTS_TO"}]})
            print("apply without confirm ->", r.content[0].text[:200])


asyncio.run(main())