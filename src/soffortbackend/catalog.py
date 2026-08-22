"""Validation for opaque, phone-issued MCP property handles."""

import re

PROPERTY_KEY_PATTERN = re.compile(r"^vault\.[A-Za-z0-9_-]{43}$")
MAX_REQUESTED_PROPERTIES = 100
MAX_AVAILABLE_PROPERTIES = 1_024


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
