"""Tests for opaque property handles returned by approved phone discovery."""

import pytest
from conftest import EMAIL_KEY, EMAIL_METADATA, NAME_KEY

from soffortbackend.catalog import parse_property_keys, validate_property_metadata
from soffortbackend.models import PropertyMetadata


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


def test_value_free_property_index_validation() -> None:
    assert validate_property_metadata((EMAIL_METADATA,)) == (EMAIL_METADATA,)


@pytest.mark.parametrize(
    "metadata",
    [
        (EMAIL_METADATA, EMAIL_METADATA),
        (PropertyMetadata("unknown", "Email", "email", "moderate"),),
        (PropertyMetadata(EMAIL_KEY, "", "email", "moderate"),),
        (PropertyMetadata(EMAIL_KEY, "Email", "Email Address", "moderate"),),
        (PropertyMetadata(EMAIL_KEY, "Email", "email", "unknown"),),
    ],
)
def test_value_free_property_index_rejects_invalid_metadata(metadata) -> None:
    with pytest.raises(ValueError):
        validate_property_metadata(metadata)
