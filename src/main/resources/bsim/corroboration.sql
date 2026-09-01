-- Companion schema for BSim corroboration evidence.
-- Lives beside Ghidra's BSim tables in the same PostgreSQL database.
-- Do NOT put these objects in public / BSim's schema: `bsim createdatabase`
-- owns those tables and a Ghidra upgrade may recreate or drop them.
-- Referential integrity is advisory — no foreign keys into BSim tables.

CREATE SCHEMA IF NOT EXISTS corroboration;

CREATE TABLE IF NOT EXISTS corroboration.functions (
    exe_md5            bytea       NOT NULL,
    function_name      text        NOT NULL,
    executable_name    text        NOT NULL DEFAULT '',
    constants          text[]      NOT NULL DEFAULT '{}',
    strings            text[]      NOT NULL DEFAULT '{}',
    callees            text[]      NOT NULL DEFAULT '{}',
    truncated          boolean     NOT NULL DEFAULT false,
    -- Typed signature from the reference's DWARF, for bsim_apply_matches
    -- (apply_signatures=true). prototype is Ghidra's
    -- getPrototypeString(true, true): "int lfs_mount(lfs_t * lfs, struct lfs_config * cfg)".
    -- has_dwarf is true only when the signature source is DWARF, not analysis.
    -- gdt_path names the Data Type Archive written beside the artifact.
    prototype          text,
    calling_convention text,
    param_count        int,
    has_dwarf          boolean     NOT NULL DEFAULT false,
    gdt_path           text,
    ingested_at        timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (exe_md5, function_name)
);

-- Databases created before signatures existed.
ALTER TABLE corroboration.functions ADD COLUMN IF NOT EXISTS prototype text;
ALTER TABLE corroboration.functions ADD COLUMN IF NOT EXISTS calling_convention text;
ALTER TABLE corroboration.functions ADD COLUMN IF NOT EXISTS param_count int;
ALTER TABLE corroboration.functions ADD COLUMN IF NOT EXISTS has_dwarf boolean NOT NULL DEFAULT false;
ALTER TABLE corroboration.functions ADD COLUMN IF NOT EXISTS gdt_path text;

CREATE INDEX IF NOT EXISTS corroboration_functions_constants_gin
    ON corroboration.functions USING gin (constants);
CREATE INDEX IF NOT EXISTS corroboration_functions_strings_gin
    ON corroboration.functions USING gin (strings);
CREATE INDEX IF NOT EXISTS corroboration_functions_exe_name
    ON corroboration.functions (executable_name);
