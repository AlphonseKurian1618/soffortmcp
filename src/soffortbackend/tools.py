"""MCP tools exposed by soffortbackend."""

from typing import Annotated, Literal, Never

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict


class HelloWorldOutput(BaseModel):
    """Stable structured output returned by the hello-world tool."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message: str
    user_name: str
    server: Literal["soffortbackend"] = "soffortbackend"


class ApprovalToolError(Exception):
    """Expected, value-free approval failure safe to show to an MCP caller."""


_APPROVAL_ERROR_MESSAGES = {
    "profile_required": "Set your display name in the Soffort iPhone app, then try again.",
    "phone_not_linked": (
        "No iPhone is linked to this account. Open the Soffort app and link this iPhone."
    ),
    "notifications_unavailable": (
        "The approval notification could not be delivered. Open the Soffort app, "
        "verify notifications are enabled, and try again."
    ),
    "approval_denied": "The request was denied on the iPhone.",
    "approval_timed_out": (
        "No iPhone decision was received before the request expired. "
        "Try again and approve the new request."
    ),
    "approval_unavailable": "Phone approval is temporarily unavailable. Try again.",
}


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


def approval_error(code: str) -> Never:
    """Raise a value-free failure that the SDK converts to an MCP tool error.

    Returning ``CallToolResult(is_error=True)`` looks natural but the SDK still
    validates its absent structured content against ``HelloWorldOutput``. Raising
    here bypasses success-output validation and preserves the real failure reason.
    """
    message = _APPROVAL_ERROR_MESSAGES.get(
        code,
        "Phone approval failed. Try again.",
    )
    raise ApprovalToolError(message)
