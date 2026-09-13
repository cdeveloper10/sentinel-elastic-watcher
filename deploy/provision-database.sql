-- Creates the database and the role the platform runs as. Run once, as a superuser, against the
-- maintenance database (`postgres`), before the first deployment.
--
--   psql -h <host> -p <port> -U postgres -d postgres \
--        -v app_password="'<generated>'" -f provision-database.sql
--
-- The platform never does this itself. Creating databases and roles needs privileges the running service
-- must not hold: an account that can CREATE DATABASE can also DROP one, and the process that answers HTTP
-- is the last one that should be able to.
--
-- CREATE DATABASE cannot run inside a transaction, so this file is not atomic. It is also not idempotent —
-- a second run fails on the object that already exists, which is the honest outcome for a script that
-- provisions rather than reconciles.

CREATE ROLE sentinel_app WITH LOGIN PASSWORD :app_password;

-- No locale or template clauses: this server's defaults are correct for it, and pinning a collation that
-- the host's libc does not carry is a failure at provisioning time on some machines and a silently
-- different sort order on others. Sentinel stores no collation-sensitive uniqueness.
CREATE DATABASE sentinel_prod OWNER sentinel_app;

-- The role owns its own database and has rights nowhere else, so a leaked platform credential reaches
-- Sentinel's data and stops there.
REVOKE ALL ON DATABASE sentinel_prod FROM PUBLIC;
