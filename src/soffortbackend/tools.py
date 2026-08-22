"""MCP result contracts for phone-mediated Permi vault consent."""

from typing import Annotated, Literal, Never

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, ConfigDict

from soffortbackend.disclosure import DisclosedProperty
from soffortbackend.models import Approval, ApprovalStatus, PropertyMetadata


class PropertyMetadataOutput(BaseModel):
    """Value-free metadata for one populated vault property."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    key: str
    display_name: str
    value_type: str
    sensitivity: str


class PropertyValueOutput(PropertyMetadataOutput):
    """One explicitly approved plaintext value."""

    value: str


class ListAvailablePropertiesOutput(BaseModel):
    """Structured, value-free discovery result."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["available"]
    properties: list[PropertyMetadataOutput]


class RequestPropertiesOutput(BaseModel):
    """Structured selective-consent result returned to the MCP caller."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    status: Literal["approved", "partially_approved", "denied", "unavailable"]
    properties: list[PropertyValueOutput]
    denied_properties: list[str]
    unavailable_properties: list[str]


class ApprovalToolError(Exception):
    """Expected, value-free infrastructure failure safe for an MCP caller."""


_APPROVAL_ERROR_MESSAGES = {
    "phone_not_linked": "No iPhone is linked. Open Permi and link this iPhone, then try again.",
    "notifications_unavailable": (
        "The Permi notification could not be delivered. Open Permi, verify notifications "
        "are enabled, and try again."
    ),
    "approval_timed_out": (
        "No phone decision was received before the two-minute request expired. Try again."
    ),
    "approval_unavailable": "Phone consent is temporarily unavailable. Try again.",
    "disclosure_invalid": "The approved disclosure could not be safely verified. Try again.",
}


def list_result(
    metadata: tuple[PropertyMetadata, ...],
) -> Annotated[CallToolResult, ListAvailablePropertiesOutput]:
    """Build discovery output from the latest value-free phone index."""
    properties = [_metadata(item) for item in metadata]
    output = ListAvailablePropertiesOutput(status="available", properties=properties)
    summary = f"Found {len(properties)} available vault properties."
    return _result(output, summary)


def request_result(
    approval: Approval,
    values: tuple[DisclosedProperty, ...],
) -> Annotated[CallToolResult, RequestPropertiesOutput]:
    """Build ordered output whose cleartext exists only in structured content."""
    by_key = {item.key: item.value for item in values}
    metadata_by_key = {item.key: item for item in approval.property_metadata}
    properties = [
        PropertyValueOutput(**_metadata(metadata_by_key[key]).model_dump(), value=by_key[key])
        for key in approval.approved_keys
    ]
    denied = list(approval.denied_keys)
    unavailable = list(approval.unavailable_keys)
    if approval.status is ApprovalStatus.DENIED:
        status: Literal["approved", "partially_approved", "denied", "unavailable"] = "denied"
    elif not properties:
        status = "unavailable"
    elif denied or unavailable:
        status = "partially_approved"
    else:
        status = "approved"
    output = RequestPropertiesOutput(
        status=status,
        properties=properties,
        denied_properties=denied,
        unavailable_properties=unavailable,
    )
    summary = {
        "approved": f"The user approved {len(properties)} requested properties.",
        "partially_approved": f"The user approved {len(properties)} of the requested properties.",
        "denied": "The user denied the request.",
        "unavailable": "None of the requested properties is available in this Permi vault.",
    }[status]
    return _result(output, summary)


def approval_error(code: str) -> Never:
    """Raise before SDK success-schema validation, preserving the safe reason."""
    raise ApprovalToolError(_APPROVAL_ERROR_MESSAGES.get(code, "Phone consent failed. Try again."))


def _metadata(definition: PropertyMetadata) -> PropertyMetadataOutput:
    return PropertyMetadataOutput(
        key=definition.key,
        display_name=definition.display_name,
        value_type=definition.value_type,
        sensitivity=definition.sensitivity,
    )


def _result(output: BaseModel, summary: str) -> CallToolResult:
    # Values are intentionally absent from text content, which is commonly
    # copied into UI logs independently from MCP structured content.
    return CallToolResult(
        content=[TextContent(type="text", text=summary)],
        structured_content=output.model_dump(mode="json"),
    )
