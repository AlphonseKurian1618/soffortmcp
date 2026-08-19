"""Unit tests for the public MCP tool contract."""

import pytest

from soffortbackend.tools import hello_world


def test_hello_world_default_contract() -> None:
    result = hello_world()
    assert result.structured_content == {
        "message": "Hello, World!",
        "server": "soffortbackend",
    }
    assert result.content[0].type == "text"
    assert result.content[0].text == "Hello, World!"


def test_hello_world_trims_unicode_name() -> None:
    assert hello_world("  世界  ").structured_content == {
        "message": "Hello, 世界!",
        "server": "soffortbackend",
    }


@pytest.mark.parametrize("name", ["", "   ", "x" * 101])
def test_hello_world_rejects_invalid_name(name: str) -> None:
    with pytest.raises(ValueError, match="between 1 and 100"):
        hello_world(name)
