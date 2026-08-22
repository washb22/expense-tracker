"""Isolated SBROCOR Finance API package.

This package deliberately does not import MoneyLog's SQLAlchemy ``db`` or models.
"""

from .routes import finance_blueprint

__all__ = ["finance_blueprint"]
