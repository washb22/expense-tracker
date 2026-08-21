"""Deprecated compatibility entry point for explicit MoneyLog migrations.

This module is intentionally safe to import. Run it with ``--confirm`` only
after taking and verifying a backup of the configured database.
"""

from scripts.migrate_moneylog import main


if __name__ == "__main__":
    main()
