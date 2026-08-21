"""Unit tests for approved MCP result construction."""

import pytest

from soffortbackend.tools import ApprovalToolError, approval_error, approved_hello_world


def test_approved_hello_world_contract() -> None:
    result = approved_hello_world("Alphonse")
    assert result.structured_content == {
        "message": "Hello, Alphonse!",
        "user_name": "Alphonse",
        "server": "soffortbackend",
    }
    assert result.content[0].type == "text"
    assert result.content[0].text == "Hello, Alphonse!"


def test_approved_hello_world_preserves_unicode_profile() -> None:
    assert approved_hello_world("世界").structured_content == {
        "message": "Hello, 世界!",
        "user_name": "世界",
        "server": "soffortbackend",
    }


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("profile_required", "Set your display name"),
        ("phone_not_linked", "No iPhone is linked"),
        ("notifications_unavailable", "notification could not be delivered"),
        ("approval_denied", "denied on the iPhone"),
        ("approval_timed_out", "before the request expired"),
        ("approval_unavailable", "temporarily unavailable"),
        ("unknown", "Phone approval failed"),
    ],
)
def test_approval_error_is_meaningful_and_value_free(code: str, message: str) -> None:
    """Expected failures disclose guidance but no profile or device data."""
    with pytest.raises(ApprovalToolError, match=message):
        approval_error(code)
