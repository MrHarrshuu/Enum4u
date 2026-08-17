from enum4u.tools.registry import ToolRegistry
from enum4u.tools.subfinder import SubfinderTool
from enum4u.tools.dnsx import DnsxTool
from enum4u.tools.httpx import HttpxTool
from enum4u.tools.nmap import NmapTool
from enum4u.tools.katana import KatanaTool
from enum4u.tools.nuclei import NucleiTool


def create_default_registry() -> ToolRegistry:
    registry = ToolRegistry()

    registry.register(SubfinderTool())
    registry.register(DnsxTool())
    registry.register(HttpxTool())
    registry.register(NmapTool())
    registry.register(KatanaTool())
    registry.register(NucleiTool())

    return registry
