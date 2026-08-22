"""Validation for opaque, phone-issued MCP property handles."""

import re
import unicodedata

from soffortbackend.models import PropertyMetadata

PROPERTY_KEY_PATTERN = re.compile(r"^vault\.[A-Za-z0-9_-]{43}$")
MAX_REQUESTED_PROPERTIES = 100
MAX_AVAILABLE_PROPERTIES = 1_024
SENSITIVITY_VALUES = {"low", "moderate", "sensitive", "highly_sensitive"}
VALUE_TYPE_PATTERN = re.compile(r"^[a-z][a-z_]{0,31}$")


def parse_property_keys(values: list[str]) -> tuple[str, ...]:
    """Validate ordered opaque handles returned by approved discovery."""
    if not 1 <= len(values) <= MAX_REQUESTED_PROPERTIES:
        raise ValueError("properties must contain 1 to 100 discovered property keys")
    if not all(PROPERTY_KEY_PATTERN.fullmatch(value) for value in values):
        raise ValueError("properties contains an invalid property key")
    parsed = tuple(values)
    if len(set(parsed)) != len(parsed):
        raise ValueError("properties cannot contain duplicates")
    return parsed


def validate_property_metadata(
    properties: tuple[PropertyMetadata, ...],
) -> tuple[PropertyMetadata, ...]:
    """Validate a bounded, duplicate-free, value-free phone manifest."""
    if len(properties) > MAX_AVAILABLE_PROPERTIES:
        raise ValueError("property metadata exceeds the supported bound")
    keys = [item.key for item in properties]
    if len(keys) != len(set(keys)) or any(
        PROPERTY_KEY_PATTERN.fullmatch(key) is None for key in keys
    ):
        raise ValueError("property metadata contains invalid or duplicate keys")
    for item in properties:
        label = unicodedata.normalize("NFC", item.display_name.strip())
        if not 1 <= len(label) <= 240 or any(
            unicodedata.category(character).startswith("C") for character in label
        ):
            raise ValueError("property metadata contains an invalid display name")
        if VALUE_TYPE_PATTERN.fullmatch(item.value_type) is None:
            raise ValueError("property metadata contains an invalid value type")
        if item.sensitivity not in SENSITIVITY_VALUES:
            raise ValueError("property metadata contains an invalid sensitivity")
    return properties
