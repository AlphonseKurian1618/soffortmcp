"""Unit tests for the two MCP structured-output contracts."""

from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest

from soffortbackend.catalog import PropertyKey
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
        "requested_keys": ("identity.preferredName", "contact.personalEmail"),
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
        available_keys=("contact.personalEmail",),
    )
    result = list_result(approval)
    assert result.structured_content == {
        "status": "approved",
        "properties": [
            {
                "key": "contact.personalEmail",
                "display_name": "Personal email",
                "value_type": "email",
                "sensitivity": "moderate",
            }
        ],
    }
    assert all("value" not in item for item in result.structured_content["properties"])


def test_selective_request_returns_values_only_in_structured_content() -> None:
    approval = _approval(
        status=ApprovalStatus.APPROVED,
        approved_keys=("identity.preferredName",),
        denied_keys=("contact.personalEmail",),
    )
    result = request_result(
        approval,
        (DisclosedProperty(PropertyKey.IDENTITY_PREFERRED_NAME, "Fictional Maya"),),
    )
    assert result.structured_content == {
        "status": "partially_approved",
        "properties": [
            {
                "key": "identity.preferredName",
                "display_name": "Preferred name",
                "value_type": "text",
                "sensitivity": "moderate",
                "value": "Fictional Maya",
            }
        ],
        "denied_properties": ["contact.personalEmail"],
        "unavailable_properties": [],
    }
    assert "Fictional Maya" not in result.content[0].text


def test_denial_and_unavailable_are_structured_outcomes() -> None:
    denied = request_result(_approval(status=ApprovalStatus.DENIED), ())
    unavailable = request_result(
        _approval(
            status=ApprovalStatus.APPROVED,
            unavailable_keys=("identity.preferredName", "contact.personalEmail"),
        ),
        (),
    )
    assert denied.structured_content["status"] == "denied"
    assert unavailable.structured_content["status"] == "unavailable"


def test_fully_approved_request_has_approved_status() -> None:
    approval = _approval(
        status=ApprovalStatus.APPROVED,
        approved_keys=("identity.preferredName", "contact.personalEmail"),
    )
    values = (
        DisclosedProperty(PropertyKey.IDENTITY_PREFERRED_NAME, "Fictional Maya"),
        DisclosedProperty(PropertyKey.CONTACT_PERSONAL_EMAIL, "maya@example.invalid"),
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
