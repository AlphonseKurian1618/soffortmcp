"""Tests for opaque property handles returned by approved phone discovery."""

import pytest
from conftest import EMAIL_KEY, NAME_KEY

from soffortbackend.catalog import parse_property_keys


def test_dynamic_keys_preserve_discovery_order() -> None:
    """Any valid discovered fields may be requested without a server-side catalog."""
    assert parse_property_keys([EMAIL_KEY, NAME_KEY]) == (EMAIL_KEY, NAME_KEY)


@pytest.mark.parametrize(
    "values",
    [[], ["unknown"], [EMAIL_KEY, EMAIL_KEY], [EMAIL_KEY] * 101],
)
def test_property_handles_reject_empty_invalid_duplicate_and_oversized(
    values: list[str],
) -> None:
    with pytest.raises(ValueError):
        parse_property_keys(values)
