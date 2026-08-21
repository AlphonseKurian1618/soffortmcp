"""MCP tools exposed by soffortbackend."""

from typing import Annotated, Literal

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict


class HelloWorldOutput(BaseModel):
    """Stable structured output returned by the hello-world tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message: str
    user_name: str
    server: Literal["soffortbackend"] = "soffortbackend"


def approved_hello_world(
    display_name: str,
) -> Annotated[CallToolResult, HelloWorldOutput]:
    """Build the greeting only from the profile snapshot approved on iPhone."""
    output = HelloWorldOutput(message=f"Hello, {display_name}!", user_name=display_name)
    # Supplying both representations keeps the human-facing response concise
    # while giving MCP clients a schema-validated object for reliable automation.
    return CallToolResult(
        content=[TextContent(type="text", text=output.message)],
        structured_content=output.model_dump(mode="json"),
    )


def approval_error(code: str) -> CallToolResult:
    """Return a value-free tool execution error without a profile disclosure."""
    return CallToolResult(
        content=[TextContent(type="text", text=code)],
        is_error=True,
    )
