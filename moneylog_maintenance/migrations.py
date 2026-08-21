"""Explicit schema migrations for the legacy MoneyLog database."""

from sqlalchemy import inspect, text


def migrate_ad_spend_columns(database, ad_spend_model):
    """Upgrade the ad_spend table after an operator explicitly requests it."""
    inspector = inspect(database.engine)
    if "ad_spend" not in inspector.get_table_names():
        return

    existing_cols = {column["name"] for column in inspector.get_columns("ad_spend")}
    new_cols = {
        "adset_id": "VARCHAR(100)",
        "adset_name": "VARCHAR(200)",
        "ad_id": "VARCHAR(100)",
        "ad_name": "VARCHAR(200)",
    }
    with database.engine.begin() as connection:
        for column, column_type in new_cols.items():
            if column not in existing_cols:
                connection.execute(
                    text(f"ALTER TABLE ad_spend ADD COLUMN {column} {column_type}")
                )
                print(f"[Migration] ad_spend.{column} added")

    inspector = inspect(database.engine)
    try:
        constraints = inspector.get_unique_constraints("ad_spend")
    except Exception:
        constraints = []
    constraint_names = {constraint.get("name") for constraint in constraints}
    needs_rebuild = (
        "uq_adspend_campaign_daily" in constraint_names
        or "uq_adspend_ad_daily" not in constraint_names
    )
    if not needs_rebuild:
        return

    old_columns = [column["name"] for column in inspector.get_columns("ad_spend")]
    model_columns = {column.name for column in ad_spend_model.__table__.columns}
    common_columns = [column for column in old_columns if column in model_columns]
    columns_sql = ", ".join(common_columns)

    # SQLite cannot replace this constraint in place. The operator-facing script
    # is responsible for ensuring a backup exists before invoking this rebuild.
    with database.engine.begin() as connection:
        connection.execute(text("ALTER TABLE ad_spend RENAME TO ad_spend_old"))
        ad_spend_model.__table__.create(connection)
        connection.execute(
            text(
                f"INSERT INTO ad_spend ({columns_sql}) "
                f"SELECT {columns_sql} FROM ad_spend_old"
            )
        )
        connection.execute(
            text("DELETE FROM ad_spend WHERE ad_id IS NULL OR ad_id = ''")
        )
        connection.execute(text("DROP TABLE ad_spend_old"))
    print("[Migration] ad_spend constraint rebuilt")


def run_all(database, ad_spend_model):
    """Run all currently known MoneyLog schema migrations."""
    database.create_all()
    migrate_ad_spend_columns(database, ad_spend_model)
