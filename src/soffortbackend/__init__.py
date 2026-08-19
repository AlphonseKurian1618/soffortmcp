"""Soffort's authenticated Model Context Protocol resource server."""

from soffortbackend.app import create_app
from soffortbackend.settings import Settings

__all__ = ["Settings", "create_app"]
