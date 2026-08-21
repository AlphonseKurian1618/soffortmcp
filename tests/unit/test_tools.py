"""Unit tests for approved MCP result construction."""

from soffortbackend.tools import approval_error, approved_hello_world


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


def test_approval_error_contains_no_structured_profile() -> None:
    result = approval_error("approval_denied")
    assert result.is_error is True
    assert result.structured_content is None
    assert result.content[0].text == "approval_denied"
