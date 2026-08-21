"""Reviewed property catalog shared by MCP and the Permi iPhone client."""

from dataclasses import dataclass
from enum import StrEnum


class PropertyKey(StrEnum):
    """Only values in this closed catalog may cross the phone boundary."""

    IDENTITY_LEGAL_NAME = "identity.legalName"
    IDENTITY_PREFERRED_NAME = "identity.preferredName"
    IDENTITY_DATE_OF_BIRTH = "identity.dateOfBirth"
    CONTACT_PERSONAL_EMAIL = "contact.personalEmail"
    CONTACT_PHONE = "contact.phone"
    ADDRESS_HOME = "address.home"
    ADDRESS_SHIPPING = "address.shipping"
    TRAVEL_KNOWN_TRAVELER_NUMBER = "travel.knownTravelerNumber"
    VEHICLE_DETAILS = "vehicle.details"
    GOVERNMENT_DRIVER_LICENSE_NUMBER = "government.driverLicenseNumber"
    VEHICLE_VIN = "vehicle.vin"
    GOVERNMENT_PASSPORT_NUMBER = "government.passportNumber"
    GOVERNMENT_PASSPORT_EXPIRATION = "government.passportExpiration"


@dataclass(frozen=True, slots=True)
class PropertyDefinition:
    """Value-free metadata safe to show before a disclosure."""

    key: PropertyKey
    display_name: str
    value_type: str
    sensitivity: str
    category: str


_CATALOG_ROWS = (
    (PropertyKey.IDENTITY_LEGAL_NAME, "Legal name", "text", "sensitive", "Identity"),
    (PropertyKey.IDENTITY_PREFERRED_NAME, "Preferred name", "text", "moderate", "Identity"),
    (PropertyKey.IDENTITY_DATE_OF_BIRTH, "Date of birth", "date", "sensitive", "Identity"),
    (PropertyKey.CONTACT_PERSONAL_EMAIL, "Personal email", "email", "moderate", "Contact"),
    (PropertyKey.CONTACT_PHONE, "Phone number", "phone", "moderate", "Contact"),
    (PropertyKey.ADDRESS_HOME, "Home address", "address", "sensitive", "Address"),
    (PropertyKey.ADDRESS_SHIPPING, "Shipping address", "address", "sensitive", "Address"),
    (
        PropertyKey.TRAVEL_KNOWN_TRAVELER_NUMBER,
        "Known Traveler Number",
        "identifier",
        "highly_sensitive",
        "Travel",
    ),
    (PropertyKey.VEHICLE_DETAILS, "Vehicle details", "text", "moderate", "Vehicle"),
    (
        PropertyKey.GOVERNMENT_DRIVER_LICENSE_NUMBER,
        "Driver license number",
        "identifier",
        "highly_sensitive",
        "Government",
    ),
    (
        PropertyKey.VEHICLE_VIN,
        "Vehicle identification number",
        "identifier",
        "sensitive",
        "Vehicle",
    ),
    (
        PropertyKey.GOVERNMENT_PASSPORT_NUMBER,
        "Passport number",
        "identifier",
        "highly_sensitive",
        "Government",
    ),
    (
        PropertyKey.GOVERNMENT_PASSPORT_EXPIRATION,
        "Passport expiration",
        "date",
        "sensitive",
        "Government",
    ),
)

PROPERTY_CATALOG = tuple(PropertyDefinition(*row) for row in _CATALOG_ROWS)
PROPERTY_BY_KEY = {definition.key: definition for definition in PROPERTY_CATALOG}


def parse_property_keys(values: list[str]) -> tuple[PropertyKey, ...]:
    """Validate a non-empty, ordered, duplicate-free request."""
    if not 1 <= len(values) <= len(PROPERTY_CATALOG):
        raise ValueError("properties must contain 1 to 13 catalog keys")
    try:
        parsed = tuple(PropertyKey(value) for value in values)
    except ValueError as error:
        raise ValueError("properties contains an unknown catalog key") from error
    if len(set(parsed)) != len(parsed):
        raise ValueError("properties cannot contain duplicates")
    return parsed
