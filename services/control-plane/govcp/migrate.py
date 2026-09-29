"""Schema migration, run once per start by the cp-migrate job as `cp_owner` (never by the app)."""
from __future__ import annotations

import os
import sys
import time

import psycopg

SCHEMA = r"""
CREATE TABLE IF NOT EXISTS documents (
    collection  text        NOT NULL,
    id          text        NOT NULL,
    data        jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (collection, id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        bigint PRIMARY KEY,
    ts         text   NOT NULL,
    actor      text   NOT NULL,
    action     text   NOT NULL,
    target     text   NOT NULL,
    severity   text   NOT NULL,
    details    text   NOT NULL,          -- canonical JSON, exactly what was hashed
    prev_hash  text   NOT NULL,
    hash       text   NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS audit_log_action ON audit_log (action);

-- Defence in depth: even the owner cannot UPDATE/DELETE/TRUNCATE through normal DML.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only: % is not allowed', TG_OP;
END $$;
DROP TRIGGER IF EXISTS audit_log_no_update ON audit_log;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
DROP TRIGGER IF EXISTS audit_log_no_truncate ON audit_log;
CREATE TRIGGER audit_log_no_truncate BEFORE TRUNCATE ON audit_log
    FOR EACH STATEMENT EXECUTE FUNCTION audit_log_immutable();

-- Grants: the app role may only read and append the audit log.
REVOKE ALL ON audit_log FROM PUBLIC;
REVOKE ALL ON audit_log FROM cp_app;
GRANT SELECT, INSERT ON audit_log TO cp_app;
REVOKE ALL ON documents FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO cp_app;
"""


def main() -> int:
    dsn = os.environ["CP_OWNER_DSN"]
    for attempt in range(60):
        try:
            with psycopg.connect(dsn, autocommit=True) as c:
                c.execute(SCHEMA)
                print("migration applied")
                return 0
        except psycopg.OperationalError as e:
            print(f"waiting for database ({attempt}): {e}", file=sys.stderr)
            time.sleep(1)
    return 1


if __name__ == "__main__":
    sys.exit(main())
