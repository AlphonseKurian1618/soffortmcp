"""Focused tests for bounded phone-authored metadata decoding."""

import pytest
from conftest import EMAIL_KEY, EMAIL_METADATA

from soffortbackend.mobile_api import _metadata_tuple


def test_metadata_tuple_accepts_exact_string_contract() -> None:
    assert _metadata_tuple(
        [
            {
                "key": EMAIL_KEY,
                "display_name": "Personal · Email",
                "value_type": "email",
                "sensitivity": "moderate",
            }
        ]
    ) == (EMAIL_METADATA,)


@pytest.mark.parametrize(
    "value",
    [
        None,
        ["not-an-object"],
        [{"key": EMAIL_KEY}],
        [
            {
                "key": EMAIL_KEY,
                "display_name": 7,
                "value_type": "email",
                "sensitivity": "moderate",
            }
        ],
    ],
)
def test_metadata_tuple_rejects_malformed_members(value: object) -> None:
    with pytest.raises(ValueError):
        _metadata_tuple(value)
