SET LOCAL search_path = sentinel, public, pg_catalog;
-- Typed, bounded process observations belong to the inventory run; no command line or environment.
CREATE TABLE process_snapshot_entries (
    id uuid PRIMARY KEY,
    create_time timestamptz NOT NULL DEFAULT now(),
    update_time timestamptz NOT NULL DEFAULT now(),
    "delete" boolean NOT NULL DEFAULT false,
    collection_run_id uuid NOT NULL,
    asset_id uuid NOT NULL,
    collection_kind text NOT NULL DEFAULT 'inventory' CHECK (collection_kind = 'inventory'),
    pid integer NOT NULL CHECK (pid > 0),
    start_ticks bigint NOT NULL CHECK (start_ticks >= 0),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 256),
    state text NOT NULL CHECK (length(state) BETWEEN 1 AND 16),
    UNIQUE (collection_run_id, pid, start_ticks),
    FOREIGN KEY (collection_run_id, asset_id, collection_kind)
        REFERENCES collection_runs(id, asset_id, kind)
);
CREATE TRIGGER process_snapshot_entries_metadata_before_update
    BEFORE UPDATE ON process_snapshot_entries
    FOR EACH ROW EXECUTE FUNCTION sentinel.set_row_metadata();
