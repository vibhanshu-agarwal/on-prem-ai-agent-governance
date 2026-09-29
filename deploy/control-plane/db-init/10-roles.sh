#!/bin/sh
# First-boot init for the control-plane Postgres (gov-cp-postgres). Runs once, as the
# bootstrap superuser. Creates two roles:
#   cp_owner  owns the schema; used only by the one-shot cp-migrate job
#   cp_app    what the control plane runs as; on audit_log it gets SELECT+INSERT only
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE cp_owner LOGIN PASSWORD '${CP_OWNER_PASSWORD}';
CREATE ROLE cp_app LOGIN PASSWORD '${CP_APP_PASSWORD}';
ALTER DATABASE controlplane OWNER TO cp_owner;
REVOKE ALL ON DATABASE controlplane FROM PUBLIC;
GRANT CONNECT ON DATABASE controlplane TO cp_owner, cp_app;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname controlplane <<SQL
ALTER SCHEMA public OWNER TO cp_owner;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO cp_app;
SQL
