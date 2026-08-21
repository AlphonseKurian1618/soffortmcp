"""Tests for the closed, ordered Permi property catalog."""

import pytest

from soffortbackend.catalog import PROPERTY_CATALOG, PropertyKey, parse_property_keys


def test_catalog_has_exactly_thirteen_unique_properties() -> None:
    assert len(PROPERTY_CATALOG) == 13
    assert len({item.key for item in PROPERTY_CATALOG}) == 13
    assert parse_property_keys(["contact.personalEmail", "identity.preferredName"]) == (
        PropertyKey.CONTACT_PERSONAL_EMAIL,
        PropertyKey.IDENTITY_PREFERRED_NAME,
    )


@pytest.mark.parametrize(
    "values",
    [[], ["unknown"], ["contact.personalEmail", "contact.personalEmail"], ["x"] * 14],
)
def test_catalog_rejects_empty_unknown_duplicate_and_oversized(values: list[str]) -> None:
    with pytest.raises(ValueError):
        parse_property_keys(values)
