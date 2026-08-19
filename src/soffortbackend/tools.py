"""MCP tools exposed by soffortbackend."""

from typing import Annotated, Literal

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict


class HelloWorldOutput(BaseModel):
    """Stable structured output returned by the hello-world tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message: str
    server: Literal["soffortbackend"] = "soffortbackend"


def hello_world(name: str = "World") -> Annotated[CallToolResult, HelloWorldOutput]:
    """Greet a caller after trimming and validating a short display name."""
    normalized = name.strip()
    if not 1 <= len(normalized) <= 100:
        raise ValueError("name must contain between 1 and 100 characters after trimming")
    output = HelloWorldOutput(message=f"Hello, {normalized}!")
    # Supplying both representations keeps the human-facing response concise
    # while giving MCP clients a schema-validated object for reliable automation.
    return CallToolResult(
        content=[TextContent(type="text", text=output.message)],
        structured_content=output.model_dump(mode="json"),
    )
