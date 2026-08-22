# SBROCOR Finance API

This package is intentionally isolated from MoneyLog's SQLAlchemy models and
`tracker.db`. Its only database is selected by `SBROCOR_FINANCE_DB_PATH`, whose
production value is planned as `/var/data/render/sbrocor_finance.db`.

## Layers

`routes.py` → `service.py` → `repository.py` → `database.py` → Finance SQLite

Replacing `FinanceRepository` is the intended PostgreSQL migration seam.

## Explicit initialization

Initialization is never run during `app.py` import or production startup:

```sh
SBROCOR_FINANCE_DB_PATH=/path/to/fixture.db python scripts/init_sbrocor_finance.py
```

The connection enables `foreign_keys=ON`, `busy_timeout=10000`, and the
initializer enables WAL. A path named `tracker.db`, the production MoneyLog
path, or a path equal to the SQLite `DATABASE_URL` is rejected.

## Authentication

Every endpoint requires these server-only headers:

- `X-SBROCOR-Key-Id`
- `X-SBROCOR-Timestamp` (Unix seconds)
- `X-SBROCOR-Nonce` (at least 16 characters and unique within the allowed skew)
- `X-SBROCOR-Signature` (lowercase HMAC-SHA256 hex)

The signed bytes are:

```text
METHOD\n
PATH_WITH_QUERY\n
TIMESTAMP\n
NONCE\n
SHA256_HEX_OF_RAW_BODY
```

Secrets come only from `SBROCOR_FINANCE_HMAC_SECRET` and must be at least 32
bytes. Nonces are atomically stored in the Finance DB; replay returns HTTP 409.

## API v1

- `GET|POST /api/sbrocor/finance/v1/workspaces`
- `GET|PATCH|DELETE /api/sbrocor/finance/v1/workspaces/{id}`
- `GET /api/sbrocor/finance/v1/dashboard?workspace_id={id}`
- `GET /api/sbrocor/finance/v1/business?workspace_id={id}`
- `GET|POST /api/sbrocor/finance/v1/{transactions|categories|sales|products|platforms|ads}?workspace_id={id}`
- `GET|PATCH|DELETE /api/sbrocor/finance/v1/{resource}/{itemId}?workspace_id={id}`
- `GET /api/sbrocor/finance/v1/workspaces/{id}/export`
- `POST /api/sbrocor/finance/v1/workspaces/{id}/import?dry_run=true|false`

Import/export is JSON manifest version 1. IDs and stored Sale financial values
are retained verbatim; the API never recalculates historical Sale amounts.
