-- Run against sentinel_prod itself, as a superuser, after provision-database.sql.
--
--   psql -h <host> -p <port> -U postgres -d sentinel_prod -f provision-schema.sql
--
-- Owning the database is not owning what is in it: on PostgreSQL 15 and later the `public` schema belongs
-- to `pg_database_owner` but grants nothing to anyone else, so without this the role connects and then
-- cannot create the tables its own migration needs.
--
-- Ownership rather than table-level grants, because migrations create and alter tables. Per-table grants
-- would have to be reissued after every migration that adds one, and would be quietly wrong — the
-- application working, the next release failing — until somebody noticed.

ALTER SCHEMA public OWNER TO sentinel_app;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
