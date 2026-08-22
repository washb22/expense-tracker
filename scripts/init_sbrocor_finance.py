"""Explicitly initialize the isolated Finance DB. Never called by app import/startup."""

from sbrocor_finance.database import initialize_database


if __name__ == "__main__":
    print(initialize_database())
