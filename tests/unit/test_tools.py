"""Unit tests for the two MCP structured-output contracts."""

from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from conftest import EMAIL_KEY, EMAIL_METADATA, NAME_KEY, NAME_METADATA

from soffortbackend.disclosure import DisclosedProperty
from soffortbackend.models import Approval, ApprovalStatus
from soffortbackend.tools import ApprovalToolError, approval_error, list_result, request_result


def _approval(**changes) -> Approval:
    now = datetime.now(UTC)
    values = {
        "partition_key": "tenant:subject",
        "approval_id": str(uuid7()),
        "event_id": str(uuid7()),
        "nonce": "nonce",
        "tool_name": "request_properties",
        "arguments_hash": "hash",
        "requester": "VS Code",
        "purpose": "Book a trip",
        "requested_keys": (NAME_KEY, EMAIL_KEY),
        "created_at": now,
        "expires_at": now + timedelta(minutes=2),
    }
    values.update(changes)
    return Approval(**values)


def test_discovery_returns_metadata_without_values() -> None:
    approval = _approval(
        tool_name="list_available_properties",
        requested_keys=(),
        status=ApprovalStatus.APPROVED,
        available_keys=(EMAIL_KEY,),
        property_metadata=(EMAIL_METADATA,),
    )
    result = list_result(approval)
    assert result.structured_content == {
        "status": "approved",
        "properties": [
            {
                "key": EMAIL_KEY,
                "display_name": "Personal · Email",
                "value_type": "email",
                "sensitivity": "moderate",
            }
        ],
    }
    assert all("value" not in item for item in result.structured_content["properties"])


def test_selective_request_returns_values_only_in_structured_content() -> None:
    approval = _approval(
        status=ApprovalStatus.APPROVED,
        approved_keys=(NAME_KEY,),
        denied_keys=(EMAIL_KEY,),
        property_metadata=(NAME_METADATA, EMAIL_METADATA),
    )
    result = request_result(
        approval,
        (DisclosedProperty(NAME_KEY, "Fictional Maya"),),
    )
    assert result.structured_content == {
        "status": "partially_approved",
        "properties": [
            {
                "key": NAME_KEY,
                "display_name": "Personal · Preferred name",
                "value_type": "text",
                "sensitivity": "moderate",
                "value": "Fictional Maya",
            }
        ],
        "denied_properties": [EMAIL_KEY],
        "unavailable_properties": [],
    }
    assert "Fictional Maya" not in result.content[0].text


def test_denial_and_unavailable_are_structured_outcomes() -> None:
    denied = request_result(_approval(status=ApprovalStatus.DENIED), ())
    unavailable = request_result(
        _approval(
            status=ApprovalStatus.APPROVED,
            unavailable_keys=(NAME_KEY, EMAIL_KEY),
        ),
        (),
    )
    assert denied.structured_content["status"] == "denied"
    assert unavailable.structured_content["status"] == "unavailable"


def test_fully_approved_request_has_approved_status() -> None:
    approval = _approval(
        status=ApprovalStatus.APPROVED,
        approved_keys=(NAME_KEY, EMAIL_KEY),
        property_metadata=(NAME_METADATA, EMAIL_METADATA),
    )
    values = (
        DisclosedProperty(NAME_KEY, "Fictional Maya"),
        DisclosedProperty(EMAIL_KEY, "maya@example.invalid"),
    )
    result = request_result(approval, values)
    assert result.structured_content["status"] == "approved"


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("phone_not_linked", "No iPhone is linked"),
        ("notifications_unavailable", "notification could not be delivered"),
        ("approval_timed_out", "two-minute request expired"),
        ("approval_unavailable", "temporarily unavailable"),
        ("disclosure_invalid", "could not be safely verified"),
        ("unknown", "Phone consent failed"),
    ],
)
def test_approval_error_is_meaningful_and_value_free(code: str, message: str) -> None:
    with pytest.raises(ApprovalToolError, match=message):
        approval_error(code)
