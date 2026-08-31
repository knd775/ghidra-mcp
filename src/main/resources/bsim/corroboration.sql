-- Companion schema for BSim corroboration evidence.
-- Lives beside Ghidra's BSim tables in the same PostgreSQL database.
-- Do NOT put these objects in public / BSim's schema: `bsim createdatabase`
-- owns those tables and a Ghidra upgrade may recreate or drop them.
-- Referential integrity is advisory — no foreign keys into BSim tables.

CREATE SCHEMA IF NOT EXISTS corroboration;

CREATE TABLE IF NOT EXISTS corroboration.functions (
    exe_md5         bytea       NOT NULL,
    function_name   text        NOT NULL,
    executable_name text        NOT NULL DEFAULT '',
    constants       text[]      NOT NULL DEFAULT '{}',
    strings         text[]      NOT NULL DEFAULT '{}',
    callees         text[]      NOT NULL DEFAULT '{}',
    truncated       boolean     NOT NULL DEFAULT false,
    ingested_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (exe_md5, function_name)
);

CREATE INDEX IF NOT EXISTS corroboration_functions_constants_gin
    ON corroboration.functions USING gin (constants);
CREATE INDEX IF NOT EXISTS corroboration_functions_strings_gin
    ON corroboration.functions USING gin (strings);
CREATE INDEX IF NOT EXISTS corroboration_functions_exe_name
    ON corroboration.functions (executable_name);
